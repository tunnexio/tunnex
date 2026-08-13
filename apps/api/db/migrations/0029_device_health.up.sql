-- S7.5.3 device health (posture checks v1): client-reported facts + per-check org
-- config + an ORTHOGONAL enforcement flag. Distinct from S7.3 "device posture"
-- (= approval / known-device); this is HEALTH (healthy-device). Client-reported,
-- NOT attested — see docs/S7.5.3-decisions.md §Threat model.

-- Client-reported posture facts: lean churn table keyed by device (the 0013
-- device_status precedent — report-driven telemetry never lands on the devices row).
-- Snapshot-only in v1 (history = S7.5.3b). No org_id: keyed by device_id, org
-- authorization happens through devices (queries carry lint:cross-org).
CREATE TABLE device_health (
    device_id       uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    platform        text NOT NULL CHECK (platform IN ('macos', 'windows', 'linux', 'other')),
    os_version      text NOT NULL,
    -- NULL = the client could NOT determine this fact (e.g. the FileVault query
    -- failed): reported ABSENT, never guessed. An absent fact is class-2 of the
    -- three-way taxonomy (absence never blocks) — the check is skipped and the
    -- NULL is the "unknown" the dashboard surfaces.
    disk_encrypted  boolean,
    -- The last evaluation of these facts against the org's checks (D2 continuous
    -- eval). 'noncompliant' can be warn-only; blocking lives on devices.health_blocked.
    evaluated_state text NOT NULL CHECK (evaluated_state IN ('compliant', 'noncompliant')),
    -- Which configured checks the last report failed: [{"kind":..., "mode":...}].
    failed_checks   jsonb NOT NULL DEFAULT '[]',
    -- Client-claimed collection time (informational); reported_at is the server
    -- clock and is what staleness (D4) is measured against.
    collected_at    timestamptz,
    reported_at     timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON device_health
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Per-check org opt-in (D3): one row per CONFIGURED check; no row = that check is
-- OFF (default-off by construction — the unlock-then-opt-in convention). Future
-- checks (S7.5.3b EDR) add a kind + rows, not a migration of org columns.
CREATE TABLE org_health_checks (
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    check_kind text NOT NULL CHECK (check_kind IN ('os_version', 'disk_encryption')),
    -- warn = surface only, NEVER gates; require = a fresh non-compliant report
    -- excludes the device from desired state (block).
    mode       text NOT NULL CHECK (mode IN ('warn', 'require')),
    -- Check parameters (os_version: {"min":{"macos":"14.0","windows":"10.0"}};
    -- a platform absent from "min" is not enforced on that platform).
    param      jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, check_kind)
);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON org_health_checks
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- The enforcement flag (D7): ORTHOGONAL to approval status — a device can be
-- pending AND health-blocked (both surfaced, excluded from desired state once via
-- the readers' status='active' AND NOT health_blocked conjunction). Set/cleared
-- ONLY by evaluation of a fresh report (or the staleness sweep clearing it) —
-- never by a config write, so flipping a check on cannot mass-blackhole a fleet
-- (0%-loss grandfather, D4).
ALTER TABLE devices ADD COLUMN health_blocked boolean NOT NULL DEFAULT false;
