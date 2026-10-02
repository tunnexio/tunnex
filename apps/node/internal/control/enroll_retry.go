package control

import (
	"context"
	"errors"
	"net"
	"time"
)

// EnrollWithRetry handles the initial API-startup race without creating a new
// identity after an ambiguous enrollment. Only a failed connection establishment
// can be retried: HTTP errors, a lost response and persistence failures may follow
// token consumption and are deliberately never retried. The CSR is unchanged.
func EnrollWithRetry(ctx context.Context, apiURL, token string, csr []byte, nodeName, agentVersion string, protocolVersion int) (EnrollResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return retryInitialEnrollment(ctx, func(ctx context.Context) (EnrollResult, error) {
		attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return Enroll(attempt, apiURL, token, csr, nodeName, agentVersion, protocolVersion)
	}, func(ctx context.Context, delay time.Duration) error {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	})
}

func retryInitialEnrollment(ctx context.Context, attempt func(context.Context) (EnrollResult, error), wait func(context.Context, time.Duration) error) (EnrollResult, error) {
	delay := time.Second
	for n := 0; ; n++ {
		if err := ctx.Err(); err != nil {
			return EnrollResult{}, err
		}
		result, err := attempt(ctx)
		if err == nil {
			return result, nil
		}
		var network *net.OpError
		if n >= 11 || !errors.As(err, &network) || network.Op != "dial" || errors.Is(err, context.Canceled) {
			return EnrollResult{}, err
		}
		if err := wait(ctx, delay); err != nil {
			return EnrollResult{}, err
		}
		delay *= 2
		if delay > 10*time.Second {
			delay = 10 * time.Second
		}
	}
}
