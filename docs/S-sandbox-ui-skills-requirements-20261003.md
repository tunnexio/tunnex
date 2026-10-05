# Skills UI steering, 2026-10-03

The user explicitly added “also the skills section” to the premium Runpod-inspired sandbox UI / Create Sandbox popup request. Apply the visual redesign to the dedicated Skills section as well as the creation wizard's skill selection/configuration step. This is current user direction; optional skills, lightweight launch and existing local terminal/Codex/Claude remain unchanged.

Use existing private/curated skill APIs and immutable revision/choice-field configuration. Show selected skills, applicable configuration and requested scope clearly before create; retain availability/authorization gates and explain unavailable/empty/error states. Private credentials are never skill fields or browser request content. Do not add mandatory hosted inference, MCP, per-launch packages or executable installation. Executable/package skills and secrets brokerage require later explicit design; existing instruction skills remain inert files.

The separate UI worker owns presentation files and the premium popup redesign. This runtime worktree's small Stop/Delete correctness fix is822879f and should be preserved during integration. Do not delay the immutable09:48:49UTC native expiry or operate the active user sandbox for UI testing.
