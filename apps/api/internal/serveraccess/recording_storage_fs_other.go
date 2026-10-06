//go:build !linux && !darwin

package serveraccess

import (
	"context"
	"github.com/google/uuid"
)

// Filesystem recording is qualified only on platforms with anchored no-follow
// directory operations. Other storage adapters remain available on all hosts.
func (f *filesystemRecordingStore) Put(context.Context, uuid.UUID, uuid.UUID, int, []byte) error {
	return storageUnavailable()
}
func (f *filesystemRecordingStore) Get(context.Context, uuid.UUID, uuid.UUID, int) ([]byte, error) {
	return nil, storageUnavailable()
}
func (f *filesystemRecordingStore) Delete(context.Context, uuid.UUID, uuid.UUID, int) error {
	return storageUnavailable()
}
