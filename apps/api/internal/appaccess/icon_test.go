package appaccess

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func iconFixture(t *testing.T, format string, size int, c color.Color) string {
	t.Helper()
	pixels := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			pixels.Set(x, y, c)
		}
	}
	var out bytes.Buffer
	var err error
	if format == "jpeg" {
		err = jpeg.Encode(&out, pixels, nil)
	} else {
		err = png.Encode(&out, pixels)
	}
	if err != nil {
		t.Fatal(err)
	}
	return "data:image/" + format + ";base64," + base64.StdEncoding.EncodeToString(out.Bytes())
}

func TestApplicationIconNormalization(t *testing.T) {
	for _, format := range []string{"png", "jpeg"} {
		t.Run(format, func(t *testing.T) {
			value := iconFixture(t, format, 32, color.NRGBA{R: 80, B: 160, A: 255})
			_, encoded, _ := strings.Cut(value, ",")
			raw, _ := base64.StdEncoding.DecodeString(encoded)
			withTrailing := strings.Split(value, ",")[0] + "," + base64.StdEncoding.EncodeToString(append(raw, []byte("<script>untrusted metadata</script>")...))
			got, err := normalizeIcon(withTrailing)
			if err != nil || !strings.HasPrefix(got, "data:image/png;base64,") {
				t.Fatalf("raster not normalized: %v", err)
			}
			canonical, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "data:image/png;base64,"))
			if bytes.Contains(canonical, []byte("untrusted metadata")) {
				t.Fatal("uploaded trailing bytes retained")
			}
			if second, err := normalizeIcon(got); err != nil || second != got {
				t.Fatal("canonical icon changed on unchanged draft save", err)
			}
		})
	}
	if got, err := normalizeIcon(""); err != nil || got != "" {
		t.Fatal("default icon rejected", err)
	}
}

func TestApplicationIconRejectsUnboundedAndActiveContent(t *testing.T) {
	pngIcon := iconFixture(t, "png", 16, color.Black)
	for name, value := range map[string]string{
		"external":            "https://icons.example.test/icon.png",
		"svg":                 "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(`<svg onload="alert(1)"/>`)),
		"mime mismatch":       strings.Replace(pngIcon, "image/png", "image/jpeg", 1),
		"invalid image":       "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("not pixels")),
		"invalid base64":      "data:image/png;base64,!!!",
		"whitespace":          pngIcon + "\n",
		"oversize bytes":      "data:image/png;base64," + base64.StdEncoding.EncodeToString(make([]byte, maxIconBytes+1)),
		"oversize dimensions": iconFixture(t, "png", maxIconDimension+1, color.Black),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := normalizeIcon(value)
			code(t, err, "invalid_application_icon")
		})
	}
	// A small JPEG may expand beyond the stored PNG bound after decoding. Check
	// that limit independently of the original uploaded bytes and dimensions.
	pixels := image.NewNRGBA(image.Rect(0, 0, 512, 512))
	var seed uint32 = 123
	for y := 0; y < 512; y++ {
		for x := 0; x < 512; x++ {
			seed = 1664525*seed + 1013904223
			v := uint8(seed >> 24)
			pixels.SetNRGBA(x, y, color.NRGBA{R: v, G: v, B: v, A: 255})
		}
	}
	var compressed bytes.Buffer
	if err := jpeg.Encode(&compressed, pixels, &jpeg.Options{Quality: 10}); err != nil || compressed.Len() > maxIconBytes {
		t.Fatal("fixture must fit uploaded bound", err, compressed.Len())
	}
	_, err := normalizeIcon("data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(compressed.Bytes()))
	code(t, err, "invalid_application_icon")
}

func TestApplicationIconDigestCompatibility(t *testing.T) {
	s := NewService(nil, Config{AppBaseDomain: "apps.fixture.test", ConsoleHosts: []string{"console.other.test"}})
	in := DraftInput{Name: "Legacy", Icon: "app", OriginURL: "http://origin", GatewayID: uuid.New(), PublicHostname: "legacy.apps.fixture.test", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300}
	normalized, digest, err := s.validate(in)
	if err != nil {
		t.Fatal(err)
	}
	// Exact pre-icon authored digest projection and field order. Adding an empty
	// optional field must not invalidate previously published revision identities.
	legacy := struct {
		AllowedDestinationCIDRs []string
		OriginCAPEM             string
		OriginCADigest          string
		Name                    string
		Description             string
		Icon                    string
		OriginURL               string
		GatewayID               uuid.UUID
		PublicHostname          string
		IdleTimeoutSeconds      int32
		AbsoluteTimeoutSeconds  int32
	}{normalized.AllowedDestinationCIDRs, normalized.OriginCAPEM, normalized.OriginCADigest, normalized.Name, normalized.Description, normalized.Icon, normalized.OriginURL, normalized.GatewayID, normalized.PublicHostname, normalized.IdleTimeoutSeconds, normalized.AbsoluteTimeoutSeconds}
	b, _ := json.Marshal(legacy)
	want := sha256.Sum256(b)
	if digest != hex.EncodeToString(want[:]) {
		t.Fatal("empty icon changed a legacy revision digest")
	}
	in.IconDataURL = iconFixture(t, "jpeg", 24, color.Black)
	in.IconDataURLSet = true
	withIcon, imageDigest, err := s.validate(in)
	if err != nil || imageDigest == digest {
		t.Fatal("image missing from revision identity", err)
	}
	withIcon.IconDataURLSet = false
	_, unchanged, err := s.validate(withIcon)
	if err != nil || unchanged != imageDigest {
		t.Fatal("canonical icon or input presence changed digest", err)
	}
}
