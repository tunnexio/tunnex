//go:build !linux && !darwin

package hostposture

import (
	"context"
	"fmt"
)

func acquireCNIOperationLock(context.Context, string) (func(), error) {
	return nil, fmt.Errorf("CNI operation locking requires Linux")
}
