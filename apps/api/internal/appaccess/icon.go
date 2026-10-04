package appaccess

import (
	"bytes"
	"encoding/base64"
	"image"
	_ "image/jpeg"
	"image/png"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

const maxIconBytes = 64 * 1024
const maxIconDimension = 512

// normalizeIcon accepts only bounded raster pixels, then discards the uploaded
// container, metadata and any trailing payload by encoding a fresh PNG.
func normalizeIcon(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	invalid := func() (string, error) {
		return "", apierr.BadRequest("invalid_application_icon", "upload a PNG or JPEG up to 64 KiB and 512 by 512 pixels; the stored PNG must also fit 64 KiB")
	}
	if len(value) > len("data:image/jpeg;base64,")+base64.StdEncoding.EncodedLen(maxIconBytes) {
		return invalid()
	}
	header, encoded, ok := strings.Cut(value, ",")
	format := ""
	switch header {
	case "data:image/png;base64":
		format = "png"
	case "data:image/jpeg;base64":
		format = "jpeg"
	default:
		return invalid()
	}
	if !ok || strings.ContainsAny(encoded, "\r\n\t ") {
		return invalid()
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maxIconBytes {
		return invalid()
	}
	config, detected, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || detected != format || config.Width < 1 || config.Height < 1 || config.Width > maxIconDimension || config.Height > maxIconDimension {
		return invalid()
	}
	pixels, detected, err := image.Decode(bytes.NewReader(raw))
	if err != nil || detected != format || pixels.Bounds().Dx() != config.Width || pixels.Bounds().Dy() != config.Height {
		return invalid()
	}
	var canonical bytes.Buffer
	if err = png.Encode(&canonical, pixels); err != nil || canonical.Len() > maxIconBytes {
		return invalid()
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(canonical.Bytes()), nil
}
