# K8L-6 — an install that fails must say why, and what to run next

Story branch: `story/kubernetes-launch-fixes`. Every failed `tunnex k8s install` on 2026-11-22 ended
the same way, whatever the cause:

    error: install gateway release failed: Error: INSTALLATION FAILED: release gw-a failed, and has
    been uninstalled due to atomic being set: context deadline exceeded

Three different causes produced that one line: the node check never passing (K8L-1), the gateway
unable to reach the control plane on TCP 8443, and GKE nodes unable to pull the image. Each time the
reason was visible in the pod status or one log line — until Helm's rollback deleted the pod, ten
minutes later. Finding it took a second script that sampled the pods during the wait.

Running the install again then hit two refusals that named no way forward:

- `persisted lifecycle install operation is bound to different approved inputs`
- `control-plane lifecycle claim is "consumed", not retry-safe`

## Decision

1. While Helm waits, the CLI samples the release's pods every five seconds
   (`k8s_pod_observer.go`) and remembers the last problem: not schedulable, image cannot be pulled,
   a container that keeps failing, an init container that has not finished, running but not ready.
   For a failing or unfinished container it reads that container's last log line.
2. If the Helm operation fails, the error gains one line:
   `Last seen before the rollback: ...`. A successful operation prints nothing extra.
3. It is applied to the gateway install, the gateway upgrade and the host-posture manager.
4. The log line is bounded (600 bytes), the join token is redacted, and anything shaped like key
   material (40+ base64 characters) is replaced.
5. Sampling runs only with the real command runner. It never changes what the install does, and a
   sampling error is ignored.
6. The two retry refusals keep their first line and add the next step:
   - "different approved inputs": rerun with the earlier flags, or the exact `abort-install`
     command with the claim id filled in;
   - "consumed": the earlier attempt already enrolled the gateway; the exact
     `install --mode reuse --existing-claim <claim>` command. Other states point at `abort-install`.

## Not in this story

Making a second `install` continue by itself after a consumed claim. That changes lifecycle
semantics and needs its own paper.

## Proof

- Unit: `podProblems` on the real shapes from the walks (image pull on two pods reported once, a
  failing init container, unschedulable, healthy, unreadable); log-line bounding and redaction;
  the observer is inert for an unmarked runner and for success; both refusal texts. Suite passes
  with the race detector.
- Live: recorded in the walk when the next deliberate failure is run.
