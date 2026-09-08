# Private saved-credential test extension

`build.py` builds the Bifrost v2.0.0 transport from immutable commit
`9537b2fadf42af90eb34ed47d3d4252e1beff4a0`, adding only `saved_probe.go` and
one administrator-protected route. Upstream source and dependencies retain their
licenses; upstream LICENSE is shipped at `/app/BIFROST-LICENSE`. This extension is
Tunnex Apache-2.0 code. It does not replace or relax inference authentication.

The endpoint resolves the key inside the engine and sends one request to the
existing private LiteLLM bridge (`TUNNEX_AI_LITELLM_URL` and
`TUNNEX_AI_LITELLM_ADMIN_TOKEN`, installation configuration). It never changes
the saved key/model scope and returns status, duration and an optional bounded
failure category/source/HTTP status. Raw provider errors and secrets are never
returned. The control plane
checks organization ownership, provider, revision and endpoint before calling it.
The key never returns to the control plane or browser. Catalog checks remain
separate from inference tests. Engines without this extension refuse saved-key
tests rather than claiming success.

Build with `python3 apps/ai-engine/build.py /path/to/bifrost-source /path/to/output`.
Use a dedicated build cache. The original upstream Git checkout is untouched.
