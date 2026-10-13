# Isolated Azure local qualification

Project `tunnexazures2slocal1010` owns API 48083, agent control 48446, PostgreSQL 45440 and UI 45173. Run `prepare.py`; its private environment is ignored. Build reviewed source into `.runtime/bin/tunnex-api`, then start only this compose file with `--env-file .env`. Never print bootstrap logs or private account/token files.

`prepare-ui.py` creates owner/admin/member test accounts only in the owned azures2s database and keeps credentials in private `.runtime/ui-accounts.json`. This fixture supplies identities only, never gateway capabilities or health. Enroll a gateway with a real normal-API join token stored privately in `.runtime/gateway.env`, then start only the gateway compose using a source-verified Azure native image. Bind a Site and observe actual eligibility; do not seed readiness/capability flags.

Binaries, native image and local tests must be bound to the exact integrated source. Local CP/gateway, native components, real Azure VPN and production availability are separate proof levels. Cloud commands are bastion-only.
