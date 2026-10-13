# Archived one-shot UDP diagnostic

These files preserve the exact reviewed source executed from `/private/tmp/gcp-udp-instrumented-diagnostic-20261010`. The launcher intentionally references the separately reviewed target helper at its original private-tmp path and binds SHA256 `b459a936a7d2b1899cdda72e311a217ea60b771dd97a649291ecb63a82a8bf49`. This is an execution archive, not a deployable product or automatically replayable test.

One UDP nonce produced the exact echo in 5.578 ms, one target nonce and one gateway ingress nonce, with zero capture drops. SA identities remained unchanged. Guard revision changed 7539 to 7543; the strict diagnostic stability gate correctly remained false. The XFRM outgoing observer counted zero despite the received exact echo, so that observation cannot establish a drop. The earlier UDP timeout remains unexplained and is preserved separately. No grant, firewall, conntrack, lease, runtime or service changes occurred during this observation.

Four observer tests and one runner failure-retention test pass under Python optimization. Missing final snapshots retain captured counts and fail the stability gate. No test result establishes cloud production readiness.
