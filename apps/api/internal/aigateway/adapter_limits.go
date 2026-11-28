package aigateway

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AdapterLimits are the administrator settings of the inference adapter. See
// docs/AI-COMPAT-1-decisions.md for the meaning and ranges of each value.
type AdapterLimits struct {
	MaxOutputTokens      int
	DefaultOutputTokens  int
	MaxMessages          int
	MaxRequestBytes      int64
	MaxResponseBytes     int64
	MaxStreamBytes       int64
	BodyReadTimeout      time.Duration
	RequestTimeout       time.Duration
	StreamTimeout        time.Duration
	IdleTimeout          time.Duration
	MaxConcurrent        int
	MaxConcurrentPerSubj int
	MaxConcurrentPerOrg  int
}

// Outer bounds that components outside the API (nginx, node relay, workload
// wrapper) are sized for. Settings may not exceed them.
const (
	OuterMaxRequestBytes = 32 << 20
	OuterMaxRequest      = 30 * time.Minute
	OuterMaxStream       = 60 * time.Minute
)

func DefaultAdapterLimits() AdapterLimits {
	return AdapterLimits{
		MaxOutputTokens: 32768, DefaultOutputTokens: 4096, MaxMessages: 2048,
		MaxRequestBytes: 8 << 20, MaxResponseBytes: 16 << 20, MaxStreamBytes: 64 << 20,
		BodyReadTimeout: 60 * time.Second, RequestTimeout: 5 * time.Minute, StreamTimeout: 10 * time.Minute, IdleTimeout: 150 * time.Second,
		MaxConcurrent: 256, MaxConcurrentPerSubj: 16, MaxConcurrentPerOrg: 256,
	}
}

// LoadAdapterLimits reads TUNNEX_AI_* settings. An absent variable keeps the
// default; a malformed or out-of-range value is an error so the server refuses
// to start rather than run with an unintended limit.
func LoadAdapterLimits(getenv func(string) string) (AdapterLimits, error) {
	l := DefaultAdapterLimits()
	intVar := func(name string, dst *int, min, max int) error {
		raw := strings.TrimSpace(getenv(name))
		if raw == "" {
			return nil
		}
		v, err := strconv.Atoi(raw)
		if err != nil || v < min || v > max {
			return fmt.Errorf("%s must be an integer from %d to %d", name, min, max)
		}
		*dst = v
		return nil
	}
	bytesVar := func(name string, dst *int64, min, max int64) error {
		raw := strings.TrimSpace(getenv(name))
		if raw == "" {
			return nil
		}
		v, err := parseByteSize(raw)
		if err != nil || v < min || v > max {
			return fmt.Errorf("%s must be a size from %d to %d bytes (suffix KiB or MiB allowed)", name, min, max)
		}
		*dst = v
		return nil
	}
	durVar := func(name string, dst *time.Duration, min, max time.Duration) error {
		raw := strings.TrimSpace(getenv(name))
		if raw == "" {
			return nil
		}
		v, err := time.ParseDuration(raw)
		if err != nil {
			if n, e := strconv.Atoi(raw); e == nil {
				v, err = time.Duration(n)*time.Second, nil
			}
		}
		if err != nil || v < min || v > max {
			return fmt.Errorf("%s must be a duration from %s to %s", name, min, max)
		}
		*dst = v
		return nil
	}
	for _, check := range []error{
		intVar("TUNNEX_AI_MAX_OUTPUT_TOKENS", &l.MaxOutputTokens, 256, 1_000_000),
		intVar("TUNNEX_AI_MAX_MESSAGES", &l.MaxMessages, 1, 10_000),
		bytesVar("TUNNEX_AI_MAX_REQUEST_BYTES", &l.MaxRequestBytes, 64<<10, OuterMaxRequestBytes),
		bytesVar("TUNNEX_AI_MAX_RESPONSE_BYTES", &l.MaxResponseBytes, 1<<20, 64<<20),
		bytesVar("TUNNEX_AI_MAX_STREAM_BYTES", &l.MaxStreamBytes, 1<<20, 1<<30),
		durVar("TUNNEX_AI_BODY_READ_TIMEOUT", &l.BodyReadTimeout, 5*time.Second, 10*time.Minute),
		durVar("TUNNEX_AI_REQUEST_TIMEOUT", &l.RequestTimeout, 10*time.Second, OuterMaxRequest),
		durVar("TUNNEX_AI_STREAM_TIMEOUT", &l.StreamTimeout, 10*time.Second, OuterMaxStream),
		durVar("TUNNEX_AI_IDLE_TIMEOUT", &l.IdleTimeout, 5*time.Second, 30*time.Minute),
		intVar("TUNNEX_AI_MAX_CONCURRENT", &l.MaxConcurrent, 1, 4096),
		intVar("TUNNEX_AI_MAX_CONCURRENT_PER_SUBJECT", &l.MaxConcurrentPerSubj, 1, 1024),
		intVar("TUNNEX_AI_MAX_CONCURRENT_PER_ORG", &l.MaxConcurrentPerOrg, 1, 65_536),
	} {
		if check != nil {
			return AdapterLimits{}, check
		}
	}
	if l.DefaultOutputTokens > l.MaxOutputTokens {
		l.DefaultOutputTokens = l.MaxOutputTokens
	}
	if err := intVar("TUNNEX_AI_DEFAULT_OUTPUT_TOKENS", &l.DefaultOutputTokens, 1, l.MaxOutputTokens); err != nil {
		return AdapterLimits{}, err
	}
	return l, nil
}

func parseByteSize(raw string) (int64, error) {
	mult := int64(1)
	switch {
	case strings.HasSuffix(raw, "MiB"):
		mult, raw = 1<<20, strings.TrimSuffix(raw, "MiB")
	case strings.HasSuffix(raw, "KiB"):
		mult, raw = 1<<10, strings.TrimSuffix(raw, "KiB")
	}
	v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || v < 0 || v > (1<<40)/mult {
		return 0, fmt.Errorf("invalid size")
	}
	return v * mult, nil
}

func (l AdapterLimits) valid() bool {
	return l.MaxOutputTokens >= 1 && l.DefaultOutputTokens >= 1 && l.DefaultOutputTokens <= l.MaxOutputTokens && l.MaxMessages >= 1 &&
		l.MaxRequestBytes > 0 && l.MaxResponseBytes > 0 && l.MaxStreamBytes > 0 && l.BodyReadTimeout > 0 && l.RequestTimeout > 0 &&
		l.StreamTimeout > 0 && l.IdleTimeout > 0 && l.MaxConcurrent >= 1 && l.MaxConcurrentPerSubj >= 1 && l.MaxConcurrentPerOrg >= 1
}
