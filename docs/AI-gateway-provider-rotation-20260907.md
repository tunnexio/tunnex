# AI gateway provider-secret rotation proof — 2026-09-07

Result: **PASS**, zero provider spend. This is a Linux-container engine rotation proof with a synthetic provider; no OpenRouter account or provider secret was used.

## Verified isolation

- Docker context: `colima-tunnex-sso-review`.
- Project: `tunnexairotate0907`; network: `tunnexairotate0907_default`.
- All three planned container names, the network and both volume names were absent before creation. Every resource was labelled with the exact project and `com.tunnex.ai-proof=rotation`; volume ownership and actual container mount destinations were checked before use.
- Existing projects, including `tunnexaiwalk0907repro`, were not modified.
- Image: `maximhq/bifrost:v2.0.0@sha256:cf71be9fad4e0749b6e26cbb774c687413dad9a0970b83f4e1dadb6f503ea208`; architecture: `arm64`.

## Wire sequence and observations

1. Started a synthetic provider that checks the actual HTTP `Authorization` header on every inference request. It accepted the original fixture provider secret.
2. Started the pinned Bifrost image with the shipped `env.OPENROUTER_API_KEY` configuration, one scoped native virtual key and exact model `openrouter/openai/gpt-4o-mini`. The first request reached the provider with the original secret and returned a real HTTP completion. Scoped log statistics retained one request/five tokens.
3. Stopped that engine, changed the synthetic provider's expected secret, and sent the old secret directly: **401**, one rejected provider arrival.
4. Recreated the engine with the new provider environment value, the identical provider key ID and the same configuration/log volumes. No replacement bootstrap config was copied and the stable encryption key was preserved.
5. Sent inference with the unchanged client-facing native virtual key. The provider accepted the newly loaded secret and returned the second completion. Provider counters were exactly **two accepted, one rejected**.
6. Authenticated native virtual-key administrative readback was identical before and after rotation. Scoped persisted accounting read back **two requests/ten tokens**: history and native identity survived the restart.

This proves startup resolution of the rotated environment reference with persistent engine state. It does not prove hot reload, changing the provider key ID, changing the encryption key, real-provider revocation, or rotation of CP-issued AI credentials. The caller in this bounded proof used an unchanged scoped Bifrost key; production callers continue using the separate Tunnex AI credential path.

## Reproduction and retained state

`deploy/ai-gateway/rotation-proof/run.py` and `provider.go` contain the zero-spend reproducer. The script rejects Python optimization mode, existing planned resources and output paths, checks ownership explicitly, and stops only the exact container IDs it created. It deliberately refuses a repeat on these retained names; do not delete prior evidence to make a rerun pass.

All created containers were stopped. The following volumes and network remain for review; no infrastructure deletion was performed:

- `tunnexairotate0907_config`
- `tunnexairotate0907_logs`
- `tunnexairotate0907_default`

Redacted committed result: `walk-artifacts/ai-gateway-20260907/provider-rotation.json`.
Local original: `/private/tmp/tunnexairotate0907-results/result.json`.
Result SHA-256: `2dea51deaa1a3ad887f3e8915be6e02147893a858d5688643f248405dd7cab60`.

Created/stopped container IDs:

- `0b425d2a8de0eba8dc71fd96998ceff9549370ea6416f1f59d04acc2520fa5b6`
- `d4ea0613be343a184e5f8a6da639baa7f10d3a7b6eec076e5d092aad2f285347`
- `6d61c3db8768761735bf7445dd80c9e07e3ef44525e9e0ed3941ae5c5c957e43`
