// Package apierr renders domain errors as the standard API error envelope
// defined in openapi/openapi.yaml: {error:{code,message,request_id,details}}.
// Services return *apierr.Error; the HTTP layer calls Write to serialize it.
package apierr

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

// Detail is a field-level problem (e.g. a validation failure).
type Detail struct {
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// Error is a typed API error carrying an HTTP status and a stable code.
type Error struct {
	Status  int
	Code    string
	Message string
	Details []Detail
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// New builds an Error with an explicit status.
func New(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

func BadRequest(code, msg string) *Error { return New(http.StatusBadRequest, code, msg) }
func Forbidden(code, msg string) *Error  { return New(http.StatusForbidden, code, msg) }
func NotFound(code, msg string) *Error   { return New(http.StatusNotFound, code, msg) }
func Conflict(code, msg string) *Error   { return New(http.StatusConflict, code, msg) }

// Internal is a generic 500 that never leaks internal detail.
func Internal() *Error {
	return New(http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
}

// envelope mirrors the OpenAPI Error schema exactly.
type envelope struct {
	Error struct {
		Code      string   `json:"code"`
		Message   string   `json:"message"`
		RequestID string   `json:"request_id,omitempty"`
		Details   []Detail `json:"details,omitempty"`
	} `json:"error"`
}

// Write serializes err as the standard envelope. Any non-*Error becomes a
// generic 500 so internal details are never exposed.
func Write(w http.ResponseWriter, r *http.Request, err error) {
	reqID := middleware.GetReqID(r.Context())

	var apiErr *Error
	if !errors.As(err, &apiErr) {
		// S11 D3.4 — DIAGNOSIS-FROM-LOGS, NOT FROM A REPRO. An unmapped error becomes a generic 500 whose
		// body deliberately carries no internal detail, so unless the WRAPPED CAUSE is logged here it is
		// destroyed at this line and the only record is `status:500`. That is exactly how the audit-nil
		// defect (a NOT NULL violation 500ing every audited DELETE) stayed invisible until it was
		// reproduced against the DB directly. The request_id ties the log line to the client's response.
		slog.ErrorContext(r.Context(), "internal_error",
			"request_id", reqID, "method", r.Method, "path", r.URL.Path, "cause", err)
		apiErr = Internal()
	}

	var body envelope
	body.Error.Code = apiErr.Code
	body.Error.Message = apiErr.Message
	body.Error.RequestID = reqID
	body.Error.Details = apiErr.Details

	w.Header().Set("Content-Type", "application/json")
	if reqID != "" {
		w.Header().Set("X-Request-Id", reqID)
	}
	w.WriteHeader(apiErr.Status)
	_ = json.NewEncoder(w).Encode(body)
}
