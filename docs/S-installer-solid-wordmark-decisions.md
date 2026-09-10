# Installer solid wordmark

User disposition (2026-09-10): fix the EX colour variation visible in the terminal installer.

Locked: render every EX row using the same red foreground. Reuse the POSIX installer's existing red and the Windows console Red foreground; remove per-row gradient selection. Preserve glyphs, spacing, motion, no-colour handling, database choices and all host operations.

Validation: offline preview isolation, shell syntax, and actual preview output in truecolour, 256-colour and basic terminal modes. Windows runtime verification is conditional on PowerShell availability. Public publication requires the existing source-sync and deployment flow; no merge is authorized by this change request.
