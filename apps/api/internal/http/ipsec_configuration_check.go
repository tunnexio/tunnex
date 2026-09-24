package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func authorizeIPsecConfigurationCheck(ctx context.Context, org uuid.UUID) (context.Context, error) {
	ctx, err := authorize(ctx, org, rbac.PermIPsecManage)
	if err != nil {
		return ctx, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if p.UserID == uuid.Nil || p.IsMachine() {
		return ctx, apierr.Forbidden("forbidden", "a verified user is required to check IPsec configuration")
	}
	return ctx, nil
}
func (apiServer) CheckIPsecConfiguration(ctx context.Context, req api.CheckIPsecConfigurationRequestObject) (api.CheckIPsecConfigurationResponseObject, error) {
	ctx, err := authorizeIPsecConfigurationCheck(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, invalidIPsecConfiguration()
	}
	input, err := privateIPsecConfiguration(*req.Body)
	if err != nil {
		return nil, err
	}
	if err := ipsec.ValidateAWSStaticConfig(input); err != nil {
		var validation *ipsec.ConfigValidationError
		if !errors.As(err, &validation) {
			return nil, invalidIPsecConfiguration()
		}
		field := validation.Field
		if validation.TunnelSlot > 0 {
			field = fmt.Sprintf("tunnels[%d].%s", validation.TunnelSlot, field)
		}
		failure := apierr.BadRequest(string(validation.Code), "IPsec configuration is invalid")
		failure.Details = []apierr.Detail{{Field: field, Message: "invalid field"}}
		return nil, failure
	}
	return api.CheckIPsecConfiguration200JSONResponse{Body: api.IPsecConfigurationCheckResult{Valid: true}, Headers: api.CheckIPsecConfiguration200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func invalidIPsecConfiguration() error {
	return apierr.BadRequest("invalid_ipsec_configuration", "invalid IPsec configuration request")
}
func isIPsecConfigurationCheckRequest(r *http.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	return r.Method == http.MethodPost && len(parts) == 6 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "organizations" && parts[4] == "ipsec" && parts[5] == "configuration-check"
}
func validateIPsecConfigurationCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isIPsecConfigurationCheckRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		org, err := uuid.Parse(parts[3])
		if err != nil {
			apierr.Write(w, r, invalidIPsecConfiguration())
			return
		}
		ctx, err := authorizeIPsecConfigurationCheck(r.Context(), org)
		if err != nil {
			apierr.Write(w, r, err)
			return
		}
		r = r.WithContext(ctx)
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128*1024))
		if err != nil {
			apierr.Write(w, r, invalidIPsecConfiguration())
			return
		}
		// Clear the bounded copy after downstream validation/handler completes. Go's
		// decoder/request strings cannot guarantee total plaintext memory erasure.
		defer clear(body)
		if !singleUniqueJSON(body) {
			apierr.Write(w, r, invalidIPsecConfiguration())
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

// Reject duplicate keys at every object depth and extra JSON values. A depth
// bound prevents deeply nested rejected inputs from consuming unbounded stack.
func singleUniqueJSON(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 32 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		delim, container := token.(json.Delim)
		if !container {
			return true
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return false
				}
				name, ok := key.(string)
				if !ok || keys[name] {
					return false
				}
				keys[name] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for decoder.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !value(0) {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}

func privateIPsecConfiguration(body api.IPsecConfigurationCheckInput) (ipsec.StaticConfig, error) {
	// The storage-independent validator intentionally omits PSKs from JSON. Map
	// the private request DTO explicitly; never log/serialize this intermediate.
	input := ipsec.StaticConfig{Mode: string(body.Mode), CustomerOutsideAddress: body.CustomerOutsideAddress, LocalPrefixes: body.LocalPrefixes, RemotePrefixes: body.RemotePrefixes, Tunnels: make([]ipsec.StaticTunnel, len(body.Tunnels))}
	for i, t := range body.Tunnels {
		if t.Psk == nil {
			return ipsec.StaticConfig{}, invalidIPsecConfiguration()
		}
		input.Tunnels[i] = ipsec.StaticTunnel{OutsideAddress: t.OutsideAddress, InsideCIDR: t.InsideCidr, CustomerInsideAddress: t.CustomerInsideAddress, CloudInsideAddress: t.CloudInsideAddress, PSK: *t.Psk}
	}
	return input, nil
}
