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
	"strings"
)

const MaxAudioBytes = 8 << 20
const MaxMediaResponseBytes = 32 << 20

// InferencePathMode is an exact route allowlist, never a generic proxy prefix.
func InferencePathMode(path string) (ModelMode, bool) {
	switch path {
	case "/v1/chat/completions", "/anthropic/v1/messages":
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

func normalizedModeJSON(body []byte, mode ModelMode) ([]byte, string, error) {
	fields := "model "
	switch mode {
	case ModeCompletion:
		fields += "prompt max_tokens temperature stream"
	case ModeEmbedding:
		fields += "input encoding_format dimensions"
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
		valid = modeString(p, "prompt", 1, 65536) && modeNumber(p, "max_tokens", 1, 4096, true) && modeNumber(p, "temperature", 0, 2, false) && modeBool(p, "stream")
		if p["max_tokens"] == nil {
			p["max_tokens"] = json.RawMessage("1024")
		}
	case ModeEmbedding:
		valid = modeStrings(p, "input", true, 128, 65536) && modeEnum(p, "encoding_format", "float", "base64") && modeNumber(p, "dimensions", 1, 65536, true)
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
