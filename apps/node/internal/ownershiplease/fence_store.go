package ownershiplease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// FenceStore persists the complete pool-fence set independently of the active
// lease checkpoint. Lease withdrawal must never clear this state.
type FenceStore interface {
	LoadFences(ctx context.Context) ([]PoolFence, error)
	SaveFences(ctx context.Context, fences []PoolFence) error
}

type fenceFile struct {
	Version  int         `json:"version"`
	Fences   []PoolFence `json:"fences"`
	Checksum string      `json:"checksum"`
}

type legacyPoolFence struct {
	Version               int                `json:"version"`
	Scope                 PoolScope          `json:"scope"`
	Suppressed            EffectiveOwnership `json:"suppressed"`
	ArmedAtBaseVersion    uint64             `json:"armed_at_base_version,omitempty"`
	ArmedAtBaseHash       string             `json:"armed_at_base_hash,omitempty"`
	ReleasedAtBaseVersion uint64             `json:"released_at_base_version,omitempty"`
	ReleasedAtBaseHash    string             `json:"released_at_base_hash,omitempty"`
}

type legacyFenceFile struct {
	Version  int               `json:"version"`
	Fences   []legacyPoolFence `json:"fences"`
	Checksum string            `json:"checksum"`
}

type FileFenceStore struct{ path string }

func NewFileFenceStore(path string) *FileFenceStore { return &FileFenceStore{path: path} }

func (s *FileFenceStore) LoadFences(_ context.Context) ([]PoolFence, error) {
	lock, err := statePathLock(s.path)
	if err != nil {
		return nil, err
	}
	lock.Lock()
	defer lock.Unlock()
	b, err := readBoundedStateFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := rejectDuplicateStateKeys(b); err != nil {
		return nil, err
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &header); err != nil {
		return nil, err
	}
	if header.Version == legacyFenceVersion {
		return loadLegacyFences(b)
	}
	var file fenceFile
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple ownership fence values")
		}
		return nil, err
	}
	if file.Version != FenceVersion || !hex64RE.MatchString(file.Checksum) {
		return nil, fmt.Errorf("invalid ownership fence envelope")
	}
	canonical, err := canonicalFences(file.Fences)
	if err != nil {
		return nil, err
	}
	want, err := fenceChecksum(canonical)
	if err != nil || want != file.Checksum {
		return nil, fmt.Errorf("ownership fence checksum mismatch")
	}
	return canonical, nil
}

func loadLegacyFences(b []byte) ([]PoolFence, error) {
	var file legacyFenceFile
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("multiple ownership fence values")
	}
	if file.Version != legacyFenceVersion || !hex64RE.MatchString(file.Checksum) {
		return nil, fmt.Errorf("invalid legacy ownership fence envelope")
	}
	legacyBytes, err := json.Marshal(file.Fences)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(legacyBytes)
	if hex.EncodeToString(sum[:]) != file.Checksum {
		return nil, fmt.Errorf("legacy ownership fence checksum mismatch")
	}
	out := make([]PoolFence, 0, len(file.Fences))
	for _, item := range file.Fences {
		legacy, err := canonicalEffective(item.Suppressed, true)
		if err != nil || item.Version != legacyFenceVersion || item.Scope != (PoolScope{OrgID: legacy.OrgID, SiteID: legacy.SiteID, ClusterID: legacy.ClusterID, PoolID: legacy.PoolID}) {
			return nil, fmt.Errorf("invalid legacy ownership fence")
		}
		converted := PoolFence{Version: FenceVersion, Scope: item.Scope,
			Suppressed:         PoolOwnedBaseFields{Routes: legacy.Routes, WGPeers: legacy.WGPeers, VIPMappings: legacy.VIPMappings, DNSZones: legacy.DNSZones},
			ArmedAtBaseVersion: item.ArmedAtBaseVersion, ArmedAtBaseHash: item.ArmedAtBaseHash,
			ReleasedAtBaseVersion: item.ReleasedAtBaseVersion, ReleasedAtBaseHash: item.ReleasedAtBaseHash}
		converted, err = canonicalFence(converted)
		if err != nil {
			return nil, err
		}
		out = append(out, converted)
	}
	return canonicalFences(out)
}

func (s *FileFenceStore) SaveFences(_ context.Context, fences []PoolFence) error {
	canonical, err := canonicalFences(fences)
	if err != nil {
		return err
	}
	checksum, err := fenceChecksum(canonical)
	if err != nil {
		return err
	}
	b, err := json.Marshal(fenceFile{Version: FenceVersion, Fences: canonical, Checksum: checksum})
	if err != nil {
		return err
	}
	lock, err := statePathLock(s.path)
	if err != nil {
		return err
	}
	lock.Lock()
	defer lock.Unlock()
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ownership-fence-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err == nil {
		var written int64
		written, err = io.Copy(tmp, bytes.NewReader(b))
		if err == nil && written != int64(len(b)) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(name, s.path); err != nil {
		return err
	}
	return syncDir(dir)
}

func fenceChecksum(fences []PoolFence) (string, error) {
	b, err := json.Marshal(fences)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
