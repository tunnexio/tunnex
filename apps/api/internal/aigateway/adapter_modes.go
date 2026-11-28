package aigateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const MaxAudioBytes = 8 << 20
const MaxMediaResponseBytes = 32 << 20

// InferencePathMode is an exact route allowlist, never a generic proxy prefix.
func InferencePathMode(path string) (ModelMode, bool) {
	switch path {
	case "/v1/chat/completions", "/anthropic/v1/messages", "/v1/responses":
		return ModeChat, true
	case "/v1/completions":
		return ModeCompletion, true
	case "/v1/embeddings":
		return ModeEmbedding, true
	case "/v1/audio/speech":
		return ModeAudioSpeech, true
	case "/v1/audio/transcriptions":
		return ModeAudioTranscription, true
	case "/v1/images/generations":
		return ModeImageGeneration, true
	case "/v1/videos":
		return ModeVideoGeneration, true
	case "/v1/rerank":
		return ModeRerank, true
	}
	return "", false
}

// VPNInferenceRoutes are the adapter routes relayed over the VPN: every
// synchronous mode. Video generation is an asynchronous job with follow-up
// GET routes and stays on the public origin.
func VPNInferenceRoutes() []string {
	return []string{"/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/audio/speech", "/v1/audio/transcriptions",
		"/v1/images/generations", "/v1/rerank", "/v1/responses", "/anthropic/v1/messages"}
}

// decodeModeObject rejects duplicate fields, nulls, unknown keys and trailing
// data before model authorization or any upstream side effect.
func decodeModeObject(body []byte, allowed string) (map[string]json.RawMessage, error) {
	bad := errors.New("invalid inference payload")
	d := json.NewDecoder(bytes.NewReader(body))
	if t, e := d.Token(); e != nil || t != json.Delim('{') {
		return nil, bad
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		t, e := d.Token()
		k, ok := t.(string)
		if e != nil || !ok || out[k] != nil || !slices.Contains(strings.Fields(allowed), k) {
			return nil, bad
		}
		var v json.RawMessage
		if d.Decode(&v) != nil || bytes.Equal(v, []byte("null")) {
			return nil, bad
		}
		out[k] = v
	}
	if t, e := d.Token(); e != nil || t != json.Delim('}') {
		return nil, bad
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, bad
	}
	return out, nil
}
func modeString(p map[string]json.RawMessage, k string, min, max int) bool {
	var v string
	return json.Unmarshal(p[k], &v) == nil && len(v) >= min && len(v) <= max
}
func modeEnum(p map[string]json.RawMessage, k string, values ...string) bool {
	if p[k] == nil {
		return true
	}
	var v string
	if json.Unmarshal(p[k], &v) != nil {
		return false
	}
	for _, x := range values {
		if v == x {
			return true
		}
	}
	return false
}
func modeNumber(p map[string]json.RawMessage, k string, min, max float64, integer bool) bool {
	if p[k] == nil {
		return true
	}
	var v float64
	if json.Unmarshal(p[k], &v) != nil || v < min || v > max {
		return false
	}
	return !integer || v == float64(int64(v))
}
func modeBool(p map[string]json.RawMessage, k string) bool {
	if p[k] == nil {
		return true
	}
	var b bool
	return json.Unmarshal(p[k], &b) == nil
}
func modeStrings(p map[string]json.RawMessage, k string, scalar bool, maxCount, maxLen int) bool {
	if scalar && modeString(p, k, 1, maxLen) {
		return true
	}
	var items []string
	if json.Unmarshal(p[k], &items) != nil || len(items) < 1 || len(items) > maxCount {
		return false
	}
	for _, s := range items {
		if s == "" || len(s) > maxLen {
			return false
		}
	}
	return true
}

// normalizedModeJSON validates the non-chat JSON modes with the default limits
// (video jobs use it directly).
func normalizedModeJSON(body []byte, mode ModelMode) ([]byte, string, error) {
	a := &Adapter{limits: DefaultAdapterLimits()}
	return a.normalizedModeJSON(body, mode)
}

func (a *Adapter) normalizedModeJSON(body []byte, mode ModelMode) ([]byte, string, error) {
	fields := "model "
	switch mode {
	case ModeCompletion:
		fields += "prompt max_tokens temperature stream stream_options stop top_p seed user"
	case ModeEmbedding:
		fields += "input encoding_format dimensions user"
	case ModeAudioSpeech:
		fields += "input voice response_format speed"
	case ModeImageGeneration:
		fields += "prompt n size quality response_format"
	case ModeRerank:
		fields += "query documents top_n return_documents"
	case ModeVideoGeneration:
		fields += "prompt seconds size"
	default:
		return nil, "", errors.New("unsupported mode")
	}
	p, err := decodeModeObject(body, fields)
	bad := errors.New("invalid inference payload")
	if err != nil || !modeString(p, "model", 1, 255) {
		return nil, "", bad
	}
	var model string
	_ = json.Unmarshal(p["model"], &model)
	if !engineModel.MatchString(model) {
		return nil, "", bad
	}
	valid := false
	switch mode {
	case ModeCompletion:
		valid = modeString(p, "prompt", 1, 1<<30) && modeNumber(p, "max_tokens", 1, float64(a.limits.MaxOutputTokens), true) && modeNumber(p, "temperature", 0, 2, false) && modeBool(p, "stream") &&
			modeNumber(p, "top_p", 0, 1, false) && modeNumber(p, "seed", -(1<<53), 1<<53, true) &&
			(p["stop"] == nil || stringOrList(p["stop"], 4, maxStopBytes)) && (p["user"] == nil || modeString(p, "user", 1, maxIdentifierBytes))
		if p["stream_options"] != nil {
			m, ok := strictObject(p["stream_options"])
			valid = valid && ok && onlyKeys(m, "include_usage") && (m["include_usage"] == nil || jsonBool(m["include_usage"]))
		}
		if p["max_tokens"] == nil {
			p["max_tokens"] = json.RawMessage(strconv.Itoa(a.defaultOutputTokens(model)))
		}
	case ModeEmbedding:
		valid = validEmbeddingInput(p["input"]) && modeEnum(p, "encoding_format", "float", "base64") && modeNumber(p, "dimensions", 1, 65536, true) &&
			(p["user"] == nil || modeString(p, "user", 1, maxIdentifierBytes))
	case ModeAudioSpeech:
		valid = modeString(p, "input", 1, 4096) && modeString(p, "voice", 1, 100) && modeEnum(p, "response_format", "mp3", "opus", "aac", "flac", "wav", "pcm") && modeNumber(p, "speed", 0.25, 4, false)
		var voice string
		_ = json.Unmarshal(p["voice"], &voice)
		valid = valid && regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(voice)
	case ModeImageGeneration:
		valid = modeString(p, "prompt", 1, 4096) && modeNumber(p, "n", 1, 1, true) && modeEnum(p, "size", "256x256", "512x512", "1024x1024", "1024x1536", "1536x1024", "1024x1792", "1792x1024", "auto") && modeEnum(p, "quality", "standard", "hd", "low", "medium", "high", "auto") && modeEnum(p, "response_format", "url", "b64_json")
		p["n"] = json.RawMessage("1")
	case ModeRerank:
		valid = modeString(p, "query", 1, 4096) && modeStrings(p, "documents", false, 128, 65536) && modeNumber(p, "top_n", 1, 128, true) && modeBool(p, "return_documents")
		if p["top_n"] != nil {
			var n int
			var docs []string
			_ = json.Unmarshal(p["top_n"], &n)
			_ = json.Unmarshal(p["documents"], &docs)
			valid = valid && n <= len(docs)
		}
	case ModeVideoGeneration:
		valid = modeString(p, "prompt", 1, 4096) && modeEnum(p, "seconds", "4", "8", "12") && modeEnum(p, "size", "720x1280", "1280x720")
		if p["seconds"] == nil {
			p["seconds"] = json.RawMessage(`"4"`)
		}
	}
	if !valid {
		return nil, "", bad
	}
	out, err := json.Marshal(p)
	return out, model, err
}

// Rebuild the multipart request to discard caller filenames and part headers.
// A single bounded in-memory audio file is supported; no temporary files/URLs.
func normalizedTranscription(r *http.Request) ([]byte, string, string, error) {
	bad := errors.New("invalid transcription")
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, "", "", bad
	}
	fields := map[string]string{}
	var audio []byte
	fileType := ""
	for {
		part, e := mr.NextPart()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, "", "", bad
		}
		name := part.FormName()
		if name == "file" {
			if audio != nil || part.FileName() == "" {
				return nil, "", "", bad
			}
			ct, _, e := mime.ParseMediaType(part.Header.Get("Content-Type"))
			if e != nil {
				return nil, "", "", bad
			}
			switch ct {
			case "audio/wav", "audio/x-wav", "audio/mpeg", "audio/mp3", "audio/mp4", "audio/webm", "audio/ogg", "audio/flac":
			default:
				return nil, "", "", bad
			}
			audio, e = io.ReadAll(io.LimitReader(part, MaxAudioBytes+1))
			if e != nil || len(audio) == 0 || len(audio) > MaxAudioBytes {
				return nil, "", "", bad
			}
			fileType = ct
		} else {
			if _, ok := fields[name]; ok || part.FileName() != "" {
				return nil, "", "", bad
			}
			switch name {
			case "model", "language", "prompt", "response_format", "temperature":
			default:
				return nil, "", "", bad
			}
			data, e := io.ReadAll(io.LimitReader(part, 4097))
			if e != nil || len(data) > 4096 {
				return nil, "", "", bad
			}
			fields[name] = string(data)
		}
	}
	if len(audio) == 0 || len(fields["model"]) > 255 || !engineModel.MatchString(fields["model"]) {
		return nil, "", "", bad
	}
	if v, ok := fields["language"]; ok && !regexp.MustCompile(`^[a-z]{2}$`).MatchString(v) {
		return nil, "", "", bad
	}
	if v, ok := fields["response_format"]; ok && v != "json" {
		return nil, "", "", bad
	}
	if v, ok := fields["temperature"]; ok {
		p := map[string]json.RawMessage{"temperature": json.RawMessage(v)}
		if !modeNumber(p, "temperature", 0, 1, false) || strings.TrimSpace(v) == "null" {
			return nil, "", "", bad
		}
	}
	fields["response_format"] = "json"
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if mw.WriteField(k, v) != nil {
			return nil, "", "", bad
		}
	}
	ext := map[string]string{"audio/wav": "wav", "audio/x-wav": "wav", "audio/mpeg": "mp3", "audio/mp3": "mp3", "audio/mp4": "m4a", "audio/webm": "webm", "audio/ogg": "ogg", "audio/flac": "flac"}[fileType]
	fw, e := mw.CreatePart(textproto.MIMEHeader{"Content-Disposition": {`form-data; name="file"; filename="audio.` + ext + `"`}, "Content-Type": {fileType}})
	if e != nil {
		return nil, "", "", bad
	}
	if _, e = fw.Write(audio); e != nil {
		return nil, "", "", bad
	}
	if mw.Close() != nil {
		return nil, "", "", bad
	}
	return buf.Bytes(), fields["model"], mw.FormDataContentType(), nil
}

// validEmbeddingInput accepts a string, strings, token ids or token-id arrays
// (LangChain sends token arrays by default).
func validEmbeddingInput(raw json.RawMessage) bool {
	if _, ok := jsonString(raw, 1, 1<<30); ok {
		return true
	}
	items, ok := jsonArray(raw, 1, maxEmbeddingInputs)
	if !ok {
		return false
	}
	tokens := func(list []json.RawMessage) bool {
		if len(list) < 1 || len(list) > maxEmbeddingTokens {
			return false
		}
		for _, t := range list {
			if !tokenIDPattern.MatchString(string(bytes.TrimSpace(t))) {
				return false
			}
		}
		return true
	}
	first := bytes.TrimSpace(items[0])
	switch {
	case len(first) > 0 && first[0] == '"':
		for _, item := range items {
			if _, ok := jsonString(item, 1, 1<<30); !ok {
				return false
			}
		}
		return true
	case len(first) > 0 && first[0] == '[':
		for _, item := range items {
			list, ok := jsonArray(item, 1, maxEmbeddingTokens)
			if !ok || !tokens(list) {
				return false
			}
		}
		return true
	}
	return tokens(items)
}

func modeResponseAllowed(mode ModelMode, ct string) bool {
	if ct == "application/json" {
		return mode != ModeAudioSpeech
	}
	if ct == "text/event-stream" {
		return mode == ModeChat || mode == ModeCompletion
	}
	if mode == ModeAudioSpeech {
		switch ct {
		case "audio/mpeg", "audio/mp3", "audio/wav", "audio/x-wav", "audio/ogg", "audio/opus", "audio/aac", "audio/flac", "audio/pcm", "audio/L16", "application/octet-stream":
			return true
		}
	}
	return false
}
