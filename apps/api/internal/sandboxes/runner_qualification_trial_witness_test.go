package sandboxes

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRunnerTrialOfflineWitnessPinsOriginalLifetimeAndPhysicalObservation(t *testing.T) {
	now := time.Now().UTC()
	created := now.Add(-910 * time.Second)
	expires := created.Add(900 * time.Second)
	initial := created.Add(time.Second)
	stopped := created.Add(2 * time.Second)
	resumed := created.Add(3 * time.Second)
	runtime := "exact-runtime"
	s := &RunnerQualificationService{RunnerEnrollmentService: &RunnerEnrollmentService{config: RunnerEnrollmentConfig{Profile: RunnerEnrollmentProfile{BootstrapScript: RunnerArtifact{SHA256: strings.Repeat("a", 64)}}}}}
	r := runnerTrialRecord{view: RunnerQualificationTrial{ID: uuid.New(), SandboxID: uuid.New(), CreatedAt: created, ExpiresAt: expires, RuntimeID: &runtime, Phase: "awaiting_expiry"}, bindingHash: make([]byte, 32), sourceSHA: strings.Repeat("1", 40), imageDigest: "sha256:" + strings.Repeat("b", 64), initialReady: &initial, stopped: &stopped, resumeReady: &resumed}
	w := RunnerQualificationOfflineWitness{Version: 1, TrialID: r.view.ID, SandboxID: r.view.SandboxID, RuntimeID: runtime, Generation: 3, BindingSHA256: hex.EncodeToString(r.bindingHash), SourceSHA: r.sourceSHA, CreatedAt: created, ExpiresAt: expires, TransportStoppedAt: expires.Add(-5 * time.Second), ActorExpiredAt: expires.Add(time.Second), StoppedObservedAt: expires.Add(2 * time.Second), TransportResumedAt: expires.Add(3 * time.Second), ImageDigest: r.imageDigest, MemoryMaxBytes: 134217728, MemorySwapMaxBytes: 0, PIDsMax: 64, CPUQuotaUS: 100000, CPUPeriodUS: 100000, ObserverSHA256: s.config.Profile.BootstrapScript.SHA256}
	if err := s.validateOfflineWitness(r, w, now); err != nil {
		t.Fatal("exact witnessed observation", err)
	}
	for name, mutate := range map[string]func(*RunnerQualificationOfflineWitness){"runtime": func(w *RunnerQualificationOfflineWitness) { w.RuntimeID = "other" }, "sandbox": func(w *RunnerQualificationOfflineWitness) { w.SandboxID = uuid.New() }, "generation": func(w *RunnerQualificationOfflineWitness) { w.Generation = 4 }, "TTL extension": func(w *RunnerQualificationOfflineWitness) { w.ExpiresAt = w.ExpiresAt.Add(time.Second) }, "wrong observer": func(w *RunnerQualificationOfflineWitness) { w.ObserverSHA256 = strings.Repeat("c", 64) }, "no pre-expiry disconnect": func(w *RunnerQualificationOfflineWitness) { w.TransportStoppedAt = expires }, "pre-expiry sample": func(w *RunnerQualificationOfflineWitness) { w.ActorExpiredAt = expires.Add(-time.Second) }, "running cgroup": func(w *RunnerQualificationOfflineWitness) { w.CgroupPopulated = true }, "unbounded memory": func(w *RunnerQualificationOfflineWitness) { w.MemoryMaxBytes++ }, "swap": func(w *RunnerQualificationOfflineWitness) { w.MemorySwapMaxBytes = 1 }, "late guard": func(w *RunnerQualificationOfflineWitness) {
		w.StoppedObservedAt = expires.Add(121 * time.Second)
		w.TransportResumedAt = w.StoppedObservedAt
	}, "future observation": func(w *RunnerQualificationOfflineWitness) { w.TransportResumedAt = now.Add(2 * time.Minute) }} {
		t.Run(name, func(t *testing.T) {
			changed := w
			mutate(&changed)
			if err := s.validateOfflineWitness(r, changed, now); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid witness accepted", err)
			}
		})
	}
	r.resumeReady = nil
	if err := s.validateOfflineWitness(r, w, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("without canonical resume", err)
	}
}
