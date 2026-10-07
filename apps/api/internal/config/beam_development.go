package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// BeamDevelopmentTrust loads a fixed operator-owned fixture trust file. It never
// disables TLS verification or accepts roots or probe targets from API callers.
func (c Config) BeamDevelopmentTrust() ([]byte, bool, error) {
	invalid := errors.New("invalid Beam development trust configuration")
	if !c.BeamDevAllowLoopback && c.BeamDevPublicCAFile == "" {
		return nil, false, nil
	}
	if c.Env != "development" || !c.BeamDevAllowLoopback || c.BeamDevPublicCAFile == "" || !filepath.IsAbs(c.BeamDevPublicCAFile) {
		return nil, false, invalid
	}
	path := filepath.Clean(c.BeamDevPublicCAFile)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, false, invalid
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, invalid
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 64<<10 {
		return nil, false, invalid
	}
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(data) == 0 || len(data) > 64<<10 {
		return nil, false, invalid
	}
	return data, true, nil
}
