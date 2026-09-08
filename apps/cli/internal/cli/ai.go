package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/cli/internal/api"
)

// AI uses the existing Tunnex login. Neither provider nor engine keys are
// accepted from flags or printed in call examples.
func AI(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || (args[0] != "models" && args[0] != "chat") {
		return errors.New("usage: tunnex ai models|chat --org UUID [--model ID --prompt TEXT]")
	}
	fs := flag.NewFlagSet("ai "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	org := fs.String("org", "", "organization UUID")
	model := fs.String("model", "", "exact gateway model ID")
	prompt := fs.String("prompt", "", "message")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	id, err := uuid.Parse(*org)
	if err != nil || id == uuid.Nil || fs.NArg() != 0 {
		return errors.New("pass a valid organization UUID with --org")
	}
	if args[0] == "chat" && (strings.TrimSpace(*model) == "" || len(*model) > 255 || strings.TrimSpace(*prompt) == "" || len(*prompt) > 32000) {
		return errors.New("chat requires --model and --prompt (up to 32000 bytes)")
	}
	cred, err := LoadActiveCredential()
	if err != nil {
		return err
	}
	c, err := NewAuthedClient(cred)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	var responseBody []byte
	var status int
	if args[0] == "models" {
		res, err := c.ListMyAIModels(ctx, id)
		if err != nil {
			return errors.New("could not reach the AI gateway")
		}
		defer res.Body.Close()
		status = res.StatusCode
		responseBody, err = io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
		if err != nil {
			return errors.New("could not read model list")
		}
	} else {
		body := api.AiUserChatCompletionJSONRequestBody{Model: *model, Messages: []struct {
			Content string                             `json:"content"`
			Role    api.AIInferenceRequestMessagesRole `json:"role"`
		}{{Content: *prompt, Role: api.AIInferenceRequestMessagesRoleUser}}}
		limit := 256
		stream := false
		body.MaxTokens = &limit
		body.Stream = &stream
		res, err := c.AiUserChatCompletion(ctx, id, body)
		if err != nil {
			return errors.New("could not reach the AI gateway")
		}
		defer res.Body.Close()
		status = res.StatusCode
		responseBody, err = io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
		if err != nil {
			return errors.New("could not read model response")
		}
	}
	if status == 401 {
		return errors.New("sign in again with 'tunnex login'")
	}
	if status == 403 {
		return errors.New("model access denied; ask your AI admin to grant this model to your user group")
	}
	if status != 200 {
		return fmt.Errorf("AI request failed (HTTP %d)", status)
	}
	if len(responseBody) > 2<<20 || !json.Valid(responseBody) {
		return errors.New("invalid AI response")
	}
	var value any
	if json.Unmarshal(responseBody, &value) != nil {
		return errors.New("invalid AI response")
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
