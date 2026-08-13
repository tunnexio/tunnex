-- ⛔ DEMO FIXTURES — the DESIGNED PICTURE, on a local stack (S14.5).
--
-- WHY THIS EXISTS. Every EPIC-14 screen was being reviewed against an empty database, so the founder was
-- judging EMPTY STATES while the designed screen stayed invisible. The Sites network map cost SIX review
-- rounds partly for this reason: the wireframe draws five nodes and a hub, the stack had one gateway that
-- was its own hub, and no amount of design fidelity turns two nodes into five.
--
-- ════════════════════════════════════════════════════════════════════════════════════════════════════════
-- ⛔ THE BINDING CONSTRAINT: NO FIXTURE MAY CREATE A STATE THE PRODUCT CANNOT REACH ON ITS OWN.
-- ════════════════════════════════════════════════════════════════════════════════════════════════════════
--
-- A seeded row that no product path produces is a picture of something that does not exist, and it would be
-- reviewed as though it did. So every row below is what some real path WRITES:
--
--   · a site + binding + subnet         = what POST /routed-lans writes
--   · a pending subnet                  = what POST .../subnets writes before approval
--   · node_peer_status rows             = what an agent's status report writes
--   · a revoked node/device             = what the revoke endpoints write
--
-- ⚠ AND THE HEALTH KINDS ARE **NEVER WRITTEN** — `policy_degraded_kind` is COMPUTED by PolicyHealthForNodes
-- from topology + handshake freshness. So this file cannot say "degraded"; it seeds the INPUTS (real peer
-- rows with real timestamps) and lets the control plane derive the badge. If the derivation disagrees with
-- the intent commented on each row, THE DERIVATION IS RIGHT and the comment is the bug — that disagreement
-- is itself the useful signal, because it means the fixture described a state the product does not produce.
--
-- IDEMPOTENT: fixed UUIDs + ON CONFLICT DO NOTHING. Safe to re-run.
-- GUARD: everything hangs off the demo org, which `countRealOrgs` already excludes, so this cannot fight the
-- existing real-data refusal.
-- CLOCK: every timestamp is relative to now(), so "3 minutes ago" stays 3 minutes ago on every reseed.

BEGIN;

-- ── GATEWAYS ────────────────────────────────────────────────────────────────────────────────────────────
-- 5: three site-bound, one UNBOUND (so `Route a LAN` stays reachable), one REVOKED (the revoked-badge path).
-- `endpoint` + `wg_public_key` are the hub-election capability gate (electSiteHubSet), so only the intended
-- hub carries both.
INSERT INTO nodes (id, org_id, name, status, cert_serial, agent_version, enrolled_at, last_seen_at, wg_public_key, endpoint)
VALUES
  ('01900000-0000-7000-8000-0000000f0001', '01900000-0000-7000-8000-000000000001', 'gw-us-east',   'active',  'FIXTURE-01', '0.3.0', now() - interval '30 days', now() - interval '20 seconds', 'ZmlY3R1cmVLZXlIVUIwMDAwMDAwMDAwMDAwMDAwMDA9', '198.51.100.10:51820'),
  ('01900000-0000-7000-8000-0000000f0002', '01900000-0000-7000-8000-000000000001', 'gw-eu-west',   'active',  'FIXTURE-02', '0.3.0', now() - interval '22 days', now() - interval '35 seconds', 'ZmlY3R1cmVLZXlFVTAwMDAwMDAwMDAwMDAwMDAwMDA9', ''),
  ('01900000-0000-7000-8000-0000000f0003', '01900000-0000-7000-8000-000000000001', 'gw-ap-south',  'active',  'FIXTURE-03', '0.2.9', now() - interval '14 days', now() - interval '25 seconds', 'ZmlY3R1cmVLZXlBUDAwMDAwMDAwMDAwMDAwMDAwMDA9', ''),
  ('01900000-0000-7000-8000-0000000f0004', '01900000-0000-7000-8000-000000000001', 'gw-unbound-1', 'active',  'FIXTURE-04', '0.3.0', now() - interval '2 days',  now() - interval '15 seconds', 'ZmlY3R1cmVLZXlVTjAwMDAwMDAwMDAwMDAwMDAwMDA9', ''),
  ('01900000-0000-7000-8000-0000000f0005', '01900000-0000-7000-8000-000000000001', 'gw-retired-1', 'revoked', 'FIXTURE-05', '0.2.4', now() - interval '90 days', now() - interval '9 days',   '',                                             '')
ON CONFLICT (id) DO NOTHING;

UPDATE nodes SET revoked_at = now() - interval '9 days'
 WHERE id = '01900000-0000-7000-8000-0000000f0005' AND revoked_at IS NULL;

-- ── SITES ───────────────────────────────────────────────────────────────────────────────────────────────
-- FOUR: the hub's own site plus three spokes. Three spokes is the minimum that renders as a RING rather than
-- a line, and ≥2 sites with approved subnets is what crosses the multi-site threshold so routes compile at
-- all (crossesMultiSiteThreshold).
INSERT INTO sites (id, org_id, name, link_transport, created_at)
VALUES
  ('01900000-0000-7000-8000-0000000e0001', '01900000-0000-7000-8000-000000000001', 'us-east-dc', 'wireguard', now() - interval '30 days'),
  ('01900000-0000-7000-8000-0000000e0002', '01900000-0000-7000-8000-000000000001', 'eu-lan',     'wireguard', now() - interval '22 days'),
  ('01900000-0000-7000-8000-0000000e0003', '01900000-0000-7000-8000-000000000001', 'ap-lan',     'wireguard', now() - interval '14 days'),
  ('01900000-0000-7000-8000-0000000e0004', '01900000-0000-7000-8000-000000000001', 'sa-lan',     'wireguard', now() - interval '6 days')
ON CONFLICT (id) DO NOTHING;

-- BINDINGS. `sa-lan` is deliberately left with NO gateway: it exercises the "no link exists" rendering,
-- which is a DIFFERENT fact from a link that is down and must never be drawn as one.
UPDATE nodes SET site_id = '01900000-0000-7000-8000-0000000e0001' WHERE id = '01900000-0000-7000-8000-0000000f0001';
UPDATE nodes SET site_id = '01900000-0000-7000-8000-0000000e0002' WHERE id = '01900000-0000-7000-8000-0000000f0002';
UPDATE nodes SET site_id = '01900000-0000-7000-8000-0000000e0003' WHERE id = '01900000-0000-7000-8000-0000000f0003';

-- ── SUBNETS ─────────────────────────────────────────────────────────────────────────────────────────────
-- Four APPROVED (routed) + one PENDING (populates the approval queue with a live Approve) + one PENDING that
-- OVERLAPS an approved range, so attempting to approve it renders the server's verbatim `subnet_not_disjoint`
-- refusal — the teaching text the panel exists to show, produced by the real validator rather than mocked.
INSERT INTO site_subnets (id, site_id, cidr, status, created_at)
VALUES
  ('01900000-0000-7000-8000-0000000d0001', '01900000-0000-7000-8000-0000000e0001', '10.10.0.0/16', 'approved', now() - interval '30 days'),
  ('01900000-0000-7000-8000-0000000d0002', '01900000-0000-7000-8000-0000000e0002', '10.20.0.0/16', 'approved', now() - interval '22 days'),
  ('01900000-0000-7000-8000-0000000d0003', '01900000-0000-7000-8000-0000000e0003', '10.30.0.0/16', 'approved', now() - interval '14 days'),
  ('01900000-0000-7000-8000-0000000d0004', '01900000-0000-7000-8000-0000000e0003', '10.31.0.0/24', 'approved', now() - interval '10 days'),
  ('01900000-0000-7000-8000-0000000d0005', '01900000-0000-7000-8000-0000000e0004', '10.40.0.0/16', 'pending',  now() - interval '2 hours'),
  ('01900000-0000-7000-8000-0000000d0006', '01900000-0000-7000-8000-0000000e0002', '10.30.4.0/24', 'pending',  now() - interval '40 minutes')
ON CONFLICT (id) DO NOTHING;

-- ── LINK STATE — ALL THREE TONES, DERIVED NOT DECLARED ──────────────────────────────────────────────────
-- These are `node_peer_status` rows: exactly what an agent's status report writes. The BADGE is computed
-- from their freshness by the control plane; nothing here names a health kind.
--
--   eu-west   handshake 40s ago   → fresh   → intended LINKED (and the flowing edge)
--   ap-south  handshake 20m ago   → stale   → intended DOWN
--   sa-lan    no gateway at all   → no row  → intended NO LINK (absent edge, not a red one)
INSERT INTO node_peer_status (node_id, public_key, last_handshake_at, rx_bytes, tx_bytes, updated_at)
VALUES
  ('01900000-0000-7000-8000-0000000f0001', 'ZmlY3R1cmVLZXlFVTAwMDAwMDAwMDAwMDAwMDAwMDA9', now() - interval '40 seconds', 184320041, 91238400, now()),
  ('01900000-0000-7000-8000-0000000f0002', 'ZmlY3R1cmVLZXlIVUIwMDAwMDAwMDAwMDAwMDAwMDA9', now() - interval '45 seconds', 90118400,  183001200, now()),
  ('01900000-0000-7000-8000-0000000f0001', 'ZmlY3R1cmVLZXlBUDAwMDAwMDAwMDAwMDAwMDAwMDA9', now() - interval '20 minutes', 4194304,   2097152,   now() - interval '20 minutes'),
  ('01900000-0000-7000-8000-0000000f0003', 'ZmlY3R1cmVLZXlIVUIwMDAwMDAwMDAwMDAwMDAwMDA9', now() - interval '20 minutes', 2097152,   4194304,   now() - interval '20 minutes')
ON CONFLICT (node_id, public_key) DO UPDATE
  SET last_handshake_at = EXCLUDED.last_handshake_at,
      updated_at        = EXCLUDED.updated_at;

-- ⛔ THESE UPSERT RATHER THAN DO-NOTHING, and the reason is the whole point of the fixture.
--
-- Liveness is RELATIVE TO now(). A fixture that inserts once and never updates is fresh for ninety seconds
-- and stale forever after — so the map showed every link DOWN a couple of minutes after seeding, which is
-- not the designed picture and is not a bug in the map.
--
-- A DEMO FIXTURE FOR A LIVE SYSTEM HAS TO BE RE-RUNNABLE INTO FRESHNESS. `make seed-fixtures` is now the
-- verb for "make the demo network current again", and it stays idempotent in every other respect.
UPDATE nodes SET last_seen_at = now() - interval '20 seconds'
 WHERE id IN ('01900000-0000-7000-8000-0000000f0001',
              '01900000-0000-7000-8000-0000000f0002',
              '01900000-0000-7000-8000-0000000f0004');
-- ap-south stays STALE on purpose: it is the one gateway whose offline rendering we need to see.
UPDATE nodes SET last_seen_at = now() - interval '20 minutes'
 WHERE id = '01900000-0000-7000-8000-0000000f0003';

-- ── HA HUB SET ──────────────────────────────────────────────────────────────────────────────────────────
-- Two pinned candidates, which is what crosses the HA panel's threshold so it renders the SET rather than the
-- precondition notice. `members` is ordered: [primary, standby].
UPDATE nodes SET hub_priority = 1 WHERE id = '01900000-0000-7000-8000-0000000f0001';
UPDATE nodes SET hub_priority = 2 WHERE id = '01900000-0000-7000-8000-0000000f0002';

-- NOTE: the column is `configured`, not `members` — 0043 renamed it when `demoted` was added. I wrote
-- `members` from the ORIGINAL CREATE TABLE and missed the later ALTER, which is the same error one scale
-- down as reading a screenshot instead of the source: I read ONE statement rather than the schema's history.
-- The live `\d org_hub_set` is the authority.
-- ⛔ `DO UPDATE`, NOT `DO NOTHING` — AND THAT IS A BUG FIX, NOT A PREFERENCE.
-- `make seed` already writes an org_hub_set row, so `DO NOTHING` meant THIS FIXTURE NEVER APPLIED. The live
-- `configured` held a single base-seed node, the HA panel rendered base-seed state, and nothing anywhere
-- said so. Same class as the `NET` bug and the missing OpenVPN state: a write that silently does not happen
-- looks exactly like a write that did.
--
-- ⛔ THE FIXTURE DOES NOT WRITE `demoted`, AND MY FIRST VERSION DID. That was writing into another
-- component's field: the query comments state the partition explicitly — ReconcileHubSet owns `configured`,
-- the FAILOVER CONTROLLER owns `demoted`. A hand-seeded demotion is not a stable state; the controller
-- recomputes it on the next tick, so the fixture would have been describing a world the product corrects.
--
-- Worse, seeding it EXPOSED A PERMANENT WEDGE (fixed this slice in failover.go): a nil demoted slice reaches
-- pgx as SQL NULL against a NOT NULL column, so an org with a demotion that drops below two configured hubs
-- fails EVERY tick forever. 42 consecutive failures in the CP log before it was noticed.
--
-- THE HONEST WAY TO GET A DEMOTED MEMBER IS TO EARN ONE: put ap-south in the hub set with the capability the
-- elector requires, leave its handshake stale, and THE CONTROLLER DEMOTES IT. Derived, not declared — the
-- same rule this file already follows for every health kind.
--
-- The endpoints below are what makes that possible: `electSiteHubSet` gates on endpoint + wg_public_key, and
-- eu-west and ap-south had keys but NO endpoint, so the elected set never reached two members and the
-- controller's demotion branch never ran at all.
UPDATE nodes SET endpoint = '203.0.113.20:51820' WHERE id = '01900000-0000-7000-8000-0000000f0002' AND (endpoint IS NULL OR endpoint = '');
UPDATE nodes SET endpoint = '203.0.113.30:51820' WHERE id = '01900000-0000-7000-8000-0000000f0003' AND (endpoint IS NULL OR endpoint = '');
UPDATE nodes SET hub_priority = 3 WHERE id = '01900000-0000-7000-8000-0000000f0003';

INSERT INTO org_hub_set (org_id, configured, generation, updated_at)
VALUES ('01900000-0000-7000-8000-000000000001',
        ARRAY['01900000-0000-7000-8000-0000000f0001','01900000-0000-7000-8000-0000000f0002','01900000-0000-7000-8000-0000000f0003']::uuid[],
        7, now())
ON CONFLICT (org_id) DO UPDATE
  SET configured = EXCLUDED.configured,
      generation = EXCLUDED.generation,
      updated_at = now();

-- ── OPENVPN: OPTED IN, AND ONE GATEWAY REFUSING LOUDLY ──────────────────────────────────────────────────
-- Registered fixture debt from the S14.6 review, trigger "S14.7 Routed Ranges visual review" — discharged.
-- Without these two writes the Gateways screen's OpenVPN panel could only ever render its not-opted-in
-- precondition, so the opted-in and the faulting branches were UNREVIEWABLE on localhost.
UPDATE organizations SET ovpn_enabled = true
 WHERE id = '01900000-0000-7000-8000-000000000001';

-- `ovpn_health` is NOT a column: it rides `nodes.capabilities`, which the control plane builds server-side
-- from the agent's typed report (a compromised agent cannot inject arbitrary JSON). Seeding the REPORT is
-- therefore the honest fixture — the health kind stays derived, exactly as `node_peer_status` is for liveness.
UPDATE nodes SET capabilities = capabilities || '{"ovpn_health":"ovpn_certs_absent"}'::jsonb
 WHERE id = '01900000-0000-7000-8000-0000000f0002';

-- ── CROSS-SITE DNS ──────────────────────────────────────────────────────────────────────────────────────
-- Two clean zones plus ONE ORG-WIDE CONFLICT: `*.corp` resolves differently depending on the site, which is
-- exactly the invariant the org-wide panel exists to surface and which no per-site view could show.
UPDATE sites SET dns_forwarding = '[{"domain":"*.eu.corp","resolver_ip":"10.20.0.53"},{"domain":"*.corp","resolver_ip":"10.20.0.53"}]'::jsonb
 WHERE id = '01900000-0000-7000-8000-0000000e0002' AND dns_forwarding = '[]'::jsonb;
UPDATE sites SET dns_forwarding = '[{"domain":"*.corp","resolver_ip":"10.10.0.53"}]'::jsonb
 WHERE id = '01900000-0000-7000-8000-0000000e0001' AND dns_forwarding = '[]'::jsonb;

-- ── DEVICES ─────────────────────────────────────────────────────────────────────────────────────────────
-- Connected / idle / revoked, owned by the seeded users. Pending-approval and posture states are ENTERPRISE
-- surfaces and live in the enterprise fixture file, so this one stays honest on an open stack.
-- NOTE: `devices` carries NO last_handshake_at — device liveness lives in `device_status`, the same
-- split as nodes/node_peer_status. Read from the LIVE schema after two column guesses failed; the migration
-- files describe the schema's HISTORY, the database describes its STATE, and only one of those is authority.
INSERT INTO devices (id, org_id, user_id, node_id, name, platform, public_key, assigned_ip, status, created_at, full_tunnel)
VALUES
  ('01900000-0000-7000-8000-0000000c0001', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-0000000f0001', 'macbook-owner', 'darwin',  'ZmlY3R1cmVEZXYwMDEwMDAwMDAwMDAwMDAwMDAwMDA9', '10.99.0.11', 'active',  now() - interval '20 days', false),
  ('01900000-0000-7000-8000-0000000c0002', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-0000000f0002', 'thinkpad-erin', 'windows', 'ZmlY3R1cmVEZXYwMDIwMDAwMDAwMDAwMDAwMDAwMDA9', '10.99.0.12', 'active',  now() - interval '12 days', true),
  ('01900000-0000-7000-8000-0000000c0003', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-0000000f0003', 'pixel-erin',    'android', 'ZmlY3R1cmVEZXYwMDMwMDAwMDAwMDAwMDAwMDAwMDA9', '10.99.0.13', 'active',  now() - interval '9 days',  false),
  ('01900000-0000-7000-8000-0000000c0004', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-0000000f0001', 'ipad-owner',    'ios',     'ZmlY3R1cmVEZXYwMDQwMDAwMDAwMDAwMDAwMDAwMDA9', '10.99.0.14', 'active',  now() - interval '3 days',  false),
  ('01900000-0000-7000-8000-0000000c0005', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-0000000f0002', 'old-laptop',    'linux',   'ZmlY3R1cmVEZXYwMDUwMDAwMDAwMDAwMDAwMDAwMDA9', NULL,         'revoked', now() - interval '60 days', false),
  ('01900000-0000-7000-8000-0000000c0006', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-0000000f0001', 'unapproved-phone', 'ios',  'ZmlY3R1cmVEZXYwMDYwMDAwMDAwMDAwMDAwMDAwMDA9', '10.99.0.15', 'pending',  now() - interval '1 day',   false),
  ('01900000-0000-7000-8000-0000000c0007', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-0000000f0001', 'stale-laptop',  'darwin',  'ZmlY3R1cmVEZXYwMDcwMDAwMDAwMDAwMDAwMDAwMDA9', '10.99.0.16', 'active',   now() - interval '5 days',  false),
  ('01900000-0000-7000-8000-0000000c0008', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-0000000f0002', 'ovpn-contractor', 'linux', '',                                         '10.99.0.17', 'active',   now() - interval '2 days',  false),
  ('01900000-0000-7000-8000-0000000c0009', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-0000000f0001', 'blocked-device', 'darwin', 'ZmlY3R1cmVEZXYwMDkwMDAwMDAwMDAwMDAwMDAwMDA9', '10.99.0.18', 'active',   now() - interval '4 days',  false),
  ('01900000-0000-7000-8000-0000000c0010', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-0000000f0002', 'stale-device',   'windows', 'ZmlY3R1cmVEZXYwMDEwMDAwMDAwMDAwMDAwMDAwMDA9', '10.99.0.19', 'active',   now() - interval '10 days', false)
ON CONFLICT (id) DO NOTHING;

-- ⛔ `health_blocked` IS NOT WRITTEN HERE, AND MY FIRST VERSION WROTE IT. It is a DERIVED ENFORCEMENT FACT
-- the control plane's posture sweep owns and recomputes: seeding it is the `org_hub_set.demoted` mistake a
-- second time. The sweep silently undid the write and the row read as applied.
--
-- THE INPUTS ARE SEEDED INSTEAD, and the CP derives the conclusion: a `disk_encryption` check in REQUIRE mode
-- (below) plus a device reporting `disk_encrypted = false` on a FRESH report. That exercises the sweep's real
-- behaviour deliberately rather than fighting it.

-- stale-laptop: a static-provisioned device whose baked routes predate the org's current ranges.
-- provisioned_ranges has only 2 of the 8 current subnets, so RangesStale returns true → needs_reexport = true.
-- TWO of them, because the wiring mock asserts `needs_reexport` on two devices and the fixture seeded one.
-- A mock that asserts a state the fixture cannot produce is the inversion that let 522 tests pass while the
-- POSTURE column rendered blank.
UPDATE devices SET provisioning_mode = 'static', provisioned_ranges = '["10.10.0.0/16","10.20.0.0/16"]'
 WHERE id IN ('01900000-0000-7000-8000-0000000c0007',
              '01900000-0000-7000-8000-0000000c0009');

-- Org health check configuration (disk_encryption require mode)
INSERT INTO org_health_checks (org_id, check_kind, mode, param)
VALUES ('01900000-0000-7000-8000-000000000001', 'disk_encryption', 'require', '{}')
ON CONFLICT (org_id, check_kind) DO NOTHING;

-- Device health telemetry reports
INSERT INTO device_health (device_id, platform, os_version, disk_encrypted, evaluated_state, reported_at)
VALUES
  ('01900000-0000-7000-8000-0000000c0001', 'macos',   '14.5.0', true,  'compliant',    now() - interval '1 minute'),
  ('01900000-0000-7000-8000-0000000c0002', 'windows', '11.0.0', false, 'noncompliant', now() - interval '2 minutes'),
  ('01900000-0000-7000-8000-0000000c0009', 'macos',   '14.4.0', false, 'noncompliant', now() - interval '3 minutes'),
  ('01900000-0000-7000-8000-0000000c0010', 'windows', '10.0.0', false, 'noncompliant', now() - interval '20 days'),
  -- ⛔ A REVOKED DEVICE THAT IS ALSO POSTURE-BEARING. The wiring mock asserts this shape (the badges must be
  -- SUPPRESSED on a revoked row — the bug Gateways shipped), and no seeded device had a health row on a
  -- revoked device, so the suppression could never be observed on localhost.
  ('01900000-0000-7000-8000-0000000c0005', 'macos', '13.6.0', false, 'noncompliant', now() - interval '2 minutes')
-- ⛔ `DO UPDATE`, NOT `DO NOTHING`, AND THIS IS THE BUG THAT HID `posture blocked` ENTIRELY.
--
-- `reported_at` is written as `now() - 3 minutes` (fresh), but the row already existed from an earlier seed,
-- so DO NOTHING left the ORIGINAL timestamp in place. It aged past `HealthStaleTTL` (30 minutes) while every
-- re-run reported success — so the report was stale, the state served as `unknown`, and the sweep correctly
-- cleared `health_blocked`. The device named `blocked-device` was not blocked, and nothing said so.
--
-- The `node_peer_status` block above already fixed this exact problem for GATEWAY liveness and carries the
-- reason: A DEMO FIXTURE FOR A LIVE SYSTEM HAS TO BE RE-RUNNABLE INTO FRESHNESS. Device posture is liveness
-- with a different name and never got the same treatment.
ON CONFLICT (device_id) DO UPDATE
  SET platform        = EXCLUDED.platform,
      os_version      = EXCLUDED.os_version,
      disk_encrypted  = EXCLUDED.disk_encrypted,
      evaluated_state = EXCLUDED.evaluated_state,
      reported_at     = EXCLUDED.reported_at;

-- Device liveness is a SEPARATE table, exactly as gateway liveness is. Two connected, one idle-but-seen,
-- one that has NEVER handshaked (no row at all — enrolled, never connected, which is a different fact from
-- idle and the Devices screen must not render them alike).
INSERT INTO device_status (device_id, last_handshake_at, rx_bytes, tx_bytes, updated_at)
VALUES
  ('01900000-0000-7000-8000-0000000c0001', now() - interval '30 seconds', 52428800, 10485760, now()),
  ('01900000-0000-7000-8000-0000000c0002', now() - interval '55 seconds', 83886080, 20971520, now()),
  ('01900000-0000-7000-8000-0000000c0003', now() - interval '4 hours',    1048576,  524288,   now() - interval '4 hours')
-- Same reason as device_health above: a handshake written as "30 seconds ago" is 30 seconds ago ONCE, then
-- ages forever. Device ONLINE state is derived from this clock, so DO NOTHING makes every device drift offline.
ON CONFLICT (device_id) DO UPDATE
  SET last_handshake_at = EXCLUDED.last_handshake_at,
      rx_bytes          = EXCLUDED.rx_bytes,
      tx_bytes          = EXCLUDED.tx_bytes,
      updated_at        = EXCLUDED.updated_at;

UPDATE devices SET revoked_at = now() - interval '15 days'
 WHERE id = '01900000-0000-7000-8000-0000000c0005' AND revoked_at IS NULL;

-- ── AUDIT ───────────────────────────────────────────────────────────────────────────────────────────────
-- Real action names taken from the product's own emitters, across both actor kinds. `actor_user_id IS NULL`
-- is how a SYSTEM actor is stored — the reconciler acting on its own, which the Audit Log renders
-- first-class and which a human-only fixture set would never show.
-- `actor_system` is FIRST-CLASS (S7.x) and it is TEXT — the NAME of the system actor, not a boolean. A
-- CHECK enforces `actor_user_id IS NULL OR actor_system IS NULL`: exactly one kind of actor per row. A system
-- action seeded as a NULL user would render as 'unknown', which is the opposite of the point.
INSERT INTO audit_logs (id, org_id, actor_user_id, actor_system, action, target_type, target_id, metadata, created_at)
VALUES
  ('01900000-0000-7000-8000-0000000b0001', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000002', NULL, 'site.create',        'site',   'us-east-dc',    '{"name":"us-east-dc"}',                    now() - interval '30 days'),
  ('01900000-0000-7000-8000-0000000b0002', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000002', NULL, 'site.bind_node',     'site',   'us-east-dc',    '{"node":"gw-us-east"}',                    now() - interval '30 days'),
  ('01900000-0000-7000-8000-0000000b0003', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000002', NULL, 'site.subnet_approve','subnet', '10.10.0.0/16',  '{"site":"us-east-dc"}',                    now() - interval '30 days'),
  ('01900000-0000-7000-8000-0000000b0004', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000002', NULL, 'site.create',        'site',   'eu-lan',        '{"name":"eu-lan"}',                        now() - interval '22 days'),
  ('01900000-0000-7000-8000-0000000b0005', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000002', NULL, 'device.create',      'device', 'thinkpad-erin', '{"transport":"wireguard"}',                now() - interval '12 days'),
  ('01900000-0000-7000-8000-0000000b0006', '01900000-0000-7000-8000-000000000001', NULL, 'reconciler',                                   'hub_set.promotion',  'org',    'hub-set',       '{"generation":7,"cause":"primary_stale"}', now() - interval '6 days'),
  ('01900000-0000-7000-8000-0000000b0007', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000002', NULL, 'device.revoke',      'device', 'old-laptop',    '{"reason":"decommissioned"}',              now() - interval '15 days'),
  ('01900000-0000-7000-8000-0000000b0008', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000002', NULL, 'node.revoke',        'node',   'gw-retired-1',  '{"reason":"hardware_retired"}',            now() - interval '9 days'),
  ('01900000-0000-7000-8000-0000000b0009', '01900000-0000-7000-8000-000000000001', NULL, 'reconciler',                                   'node.reconcile',     'node',   'gw-ap-south',   '{"result":"routes_pushed"}',               now() - interval '3 days'),
  ('01900000-0000-7000-8000-0000000b000a', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000002', NULL, 'site.create',        'site',   'sa-lan',        '{"name":"sa-lan"}',                        now() - interval '6 days'),
  ('01900000-0000-7000-8000-0000000b000b', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000003', NULL, 'device.create',      'device', 'pixel-erin',    '{"transport":"wireguard"}',                now() - interval '9 days'),
  ('01900000-0000-7000-8000-0000000b000c', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000000002', NULL, 'site.subnet_advertise','subnet','10.40.0.0/16',  '{"site":"sa-lan"}',                        now() - interval '2 hours')
ON CONFLICT (id) DO NOTHING;

-- ── ZERO TRUST: USER GROUPS & GROUP MEMBERS ─────────────────────────────────────────────────────────────
INSERT INTO user_groups (id, org_id, name, description, created_at)
VALUES
  ('01900000-0000-7000-8000-0000000a0001', '01900000-0000-7000-8000-000000000001', 'Engineering',  'Core Engineering and Platform Infrastructure Team', now() - interval '25 days'),
  ('01900000-0000-7000-8000-0000000a0002', '01900000-0000-7000-8000-000000000001', 'DevOps',       'Site Reliability & GitOps Operators',               now() - interval '20 days'),
  ('01900000-0000-7000-8000-0000000a0003', '01900000-0000-7000-8000-000000000001', 'Contractors',  'External Audit & Third-Party Contractors',          now() - interval '10 days')
ON CONFLICT (id) DO NOTHING;

INSERT INTO group_members (org_id, group_id, user_id, created_at)
VALUES
  ('01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-0000000a0001', '01900000-0000-7000-8000-000000000002', now() - interval '25 days'),
  ('01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-0000000a0001', '01900000-0000-7000-8000-000000000003', now() - interval '20 days'),
  ('01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-0000000a0002', '01900000-0000-7000-8000-000000000002', now() - interval '20 days'),
  ('01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-0000000a0003', '01900000-0000-7000-8000-000000000003', now() - interval '10 days')
ON CONFLICT (group_id, user_id) DO NOTHING;

-- ── RESOURCES ───────────────────────────────────────────────────────────────────────────────────────────
INSERT INTO resources (id, org_id, name, cidr, protocol, port_low, port_high, created_at)
VALUES
  ('01900000-0000-7000-8000-000000090001', '01900000-0000-7000-8000-000000000001', 'Internal Gitlab',  '10.10.1.50/32', 'tcp', 443,  443,  now() - interval '25 days'),
  ('01900000-0000-7000-8000-000000090002', '01900000-0000-7000-8000-000000000001', 'Staging Database', '10.20.4.0/24',  'tcp', 5432, 5432, now() - interval '20 days'),
  ('01900000-0000-7000-8000-000000090003', '01900000-0000-7000-8000-000000000001', 'EU LAN Services',  '10.20.0.0/16',  'any', NULL, NULL, now() - interval '15 days')
ON CONFLICT (id) DO NOTHING;

-- ── CREDENTIALS: MACHINE & CLI ─────────────────────────────────────────────────────────────────────────
INSERT INTO machine_credentials (id, org_id, name, role, token_hash, fingerprint, created_at)
VALUES
  ('01900000-0000-7000-8000-000000050001', '01900000-0000-7000-8000-000000000001', 'k8s-operator-us-east', 'operator', '\x5d41402abc4b2a76b9719d911017c592', 'mc-operator-01', now() - interval '15 days')
ON CONFLICT (id) DO NOTHING;

INSERT INTO cli_credentials (id, user_id, name, token_hash, fingerprint, created_at, last_used_at, expires_at)
VALUES
  ('01900000-0000-7000-8000-000000060001', '01900000-0000-7000-8000-000000000002', 'owner-macbook-cli', '\x098f6bcd4621d373ade4e832627b4f6f', '9a1f04c47bd2', now() - interval '30 days', now() - interval '4 minutes', now() + interval '60 days'),
  ('01900000-0000-7000-8000-000000060002', '01900000-0000-7000-8000-000000000003', 'member-thinkpad-cli', '\x1679091c5a880faf6fb5e6087eb1b2dc', '4e0b119dc3a7', now() - interval '20 days', now() - interval '2 hours', now() + interval '40 days'),
  ('01900000-0000-7000-8000-000000060003', '01900000-0000-7000-8000-000000000003', 'ci-runner-expired', '\xc3ec378b5784990924b8785c0746e8c8', '77aa12f0e94b', now() - interval '90 days', now() - interval '31 days', now() - interval '1 day')
ON CONFLICT (id) DO NOTHING;

-- ── SOFT-DELETED K8S SERVICE FOR `dst_k8s_service_vanished` WARN STATE ────────────────────────────────
INSERT INTO k8s_clusters (id, org_id, site_id, name, vip_range)
VALUES
  ('01900000-0000-7000-8000-000000050001', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-0000000e0001', 'us-east-k8s', '10.244.0.0/24')
ON CONFLICT (id) DO NOTHING;

INSERT INTO k8s_services (id, org_id, cluster_id, name, namespace, vip, port_low, port_high, created_at, deleted_at)
VALUES
  ('01900000-0000-7000-8000-000000030003', '01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-000000050001', 'legacy-vault-svc', 'default', '10.244.0.99', 8200, 8200, now() - interval '30 days', now() - interval '2 days')
ON CONFLICT (id) DO NOTHING;

-- ── POLICY RULES (COVERING ALL 4 WARN-NOT-REFUSE / WARNING STATES) ────────────────────────────────────
INSERT INTO policy_rules (id, org_id, src_kind, src_group_id, src_user_id, src_site_id, src_cidr, dst_kind, dst_resource_id, dst_group_id, dst_site_id, dst_k8s_service_id, disabled, expires_at, managed_by_machine, created_at)
VALUES
  -- Rule 1: Clean/Active Resource Grant (Engineering -> Internal Gitlab)
  ('01900000-0000-7000-8000-000000080001', '01900000-0000-7000-8000-000000000001', 'group', '01900000-0000-7000-8000-0000000a0001', NULL, NULL, NULL, 'resource', '01900000-0000-7000-8000-000000090001', NULL, NULL, NULL, false, NULL, NULL, now() - interval '25 days'),

  -- Rule 2: Clean/Active Group Grant (DevOps -> Contractors)
  ('01900000-0000-7000-8000-000000080002', '01900000-0000-7000-8000-000000000001', 'group', '01900000-0000-7000-8000-0000000a0002', NULL, NULL, NULL, 'group', NULL, '01900000-0000-7000-8000-0000000a0003', NULL, NULL, false, NULL, NULL, now() - interval '20 days'),

  -- Rule 3: ⛔ WARN STATE 1 (`cidr_outside_org_ranges`): src_kind='cidr' with CIDR 192.168.99.0/24 outside all org subnets
  ('01900000-0000-7000-8000-000000080003', '01900000-0000-7000-8000-000000000001', 'cidr', NULL, NULL, NULL, '192.168.99.0/24', 'resource', '01900000-0000-7000-8000-000000090002', NULL, NULL, NULL, false, NULL, NULL, now() - interval '15 days'),

  -- Rule 4: ⛔ WARN STATE 2 (`dst_k8s_service_vanished`): dst_kind='k8s_service' pointing at soft-deleted legacy-vault-svc
  ('01900000-0000-7000-8000-000000080004', '01900000-0000-7000-8000-000000000001', 'group', '01900000-0000-7000-8000-0000000a0001', NULL, NULL, NULL, 'k8s_service', NULL, NULL, NULL, '01900000-0000-7000-8000-000000030003', false, NULL, NULL, now() - interval '10 days'),

  -- Rule 5: ⛔ WARN STATE 3 (`enabled: false`): rule explicitly disabled (F3 toggle)
  ('01900000-0000-7000-8000-000000080005', '01900000-0000-7000-8000-000000000001', 'group', '01900000-0000-7000-8000-0000000a0003', NULL, NULL, NULL, 'resource', '01900000-0000-7000-8000-000000090003', NULL, NULL, NULL, true, NULL, NULL, now() - interval '5 days'),

  -- Rule 6: ⛔ WARN STATE 4 (`managed_by_operator`): created by operator machine credential
  ('01900000-0000-7000-8000-000000080006', '01900000-0000-7000-8000-000000000001', 'group', '01900000-0000-7000-8000-0000000a0002', NULL, NULL, NULL, 'resource', '01900000-0000-7000-8000-000000090001', NULL, NULL, NULL, false, NULL, '01900000-0000-7000-8000-000000050001', now() - interval '2 days')
ON CONFLICT (id) DO NOTHING;

-- ── ACCESS EVENTS / FLOW LOGS ───────────────────────────────────────────────────────────────────────────
INSERT INTO access_events (id, org_id, seq, node_id, occurred_at, decision, rule_id, src_device_id, src_user_id, src_ip, dst_ip, dst_resource_id, protocol, dst_port, deny_count, window_end, created_at)
VALUES
  ('01900000-0000-7000-8000-000000070001', '01900000-0000-7000-8000-000000000001', 101, '01900000-0000-7000-8000-0000000f0001', now() - interval '2 minutes',  'allow',          '01900000-0000-7000-8000-000000080001', '01900000-0000-7000-8000-0000000c0001', '01900000-0000-7000-8000-000000000002', '10.99.0.11', '10.10.1.50', '01900000-0000-7000-8000-000000090001', 'tcp', 443, 1, NULL, now() - interval '2 minutes'),
  ('01900000-0000-7000-8000-000000070002', '01900000-0000-7000-8000-000000000001', 102, '01900000-0000-7000-8000-0000000f0002', now() - interval '12 minutes', 'deny',           NULL,                                   '01900000-0000-7000-8000-0000000c0002', '01900000-0000-7000-8000-000000000003', '10.99.0.12', '10.20.4.5',  '01900000-0000-7000-8000-000000090002', 'tcp', 22,  1, NULL, now() - interval '12 minutes'),
  ('01900000-0000-7000-8000-000000070003', '01900000-0000-7000-8000-000000000001', 103, '01900000-0000-7000-8000-0000000f0001', now() - interval '1 hour',    'deny_aggregate', NULL,                                   '01900000-0000-7000-8000-0000000c0004', '01900000-0000-7000-8000-000000000002', '10.99.0.14', '10.10.9.1',  NULL,                                  'tcp', 80, 24, now() - interval '55 minutes', now() - interval '1 hour')
ON CONFLICT (id) DO NOTHING;

-- ── S14.11: A DEACTIVATED MEMBER ─────────────────────────────────────────────────────────────────────────
-- S2.6 requires `deactivated` to render DISTINCTLY: a deactivated member KEEPS their roster row (sessions
-- revoked, access frozen, still listed). That state had NO SUBJECT — measured from the API payload, all three
-- seeded members were `active`, so the distinct render was unobservable. Same shape as `posture blocked` in
-- S14.10: a designed state the fixture could not produce.
--
-- ⛔ A FOURTH MEMBER, NOT A DEACTIVATED EXISTING ONE. Deactivating one of the three would remove a ROLE from
-- the active set, and `role` is the column this screen is named for — the fixture must show all three roles
-- active AND a deactivated row, which needs four people.
--
-- `users.status` is ADMIN-OWNED, not controller-owned: `SetUserStatus` is a plain UPDATE driven by
-- DeactivateMember (`PermMemberManage`), with no reconcile loop that would undo it. So seeding it directly is
-- safe — unlike `health_blocked` or `org_hub_set.demoted`, which the CP recomputes.
INSERT INTO users (id, email, name, password_hash, email_verified_at, status, created_at)
VALUES ('01900000-0000-7000-8000-0000000b0004', 'grace@demo.tunnex.local', 'Grace Okafor',
        NULL,                        -- no local password: exercises the AUTH label's "no local password" arm
        now() - interval '90 days',  -- verified, so this row varies ONLY in status
        'deactivated', now() - interval '90 days')
ON CONFLICT (id) DO UPDATE
  SET status = EXCLUDED.status, email_verified_at = EXCLUDED.email_verified_at;

INSERT INTO memberships (org_id, user_id, role, created_at)
VALUES ('01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-0000000b0004',
        'member', now() - interval '90 days')
ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role;

-- ⛔ ONE ISOLATION PER FACT. `grace@` above carries TWO states at once — deactivated AND no local password —
-- so if her row renders wrong you cannot tell which state caused it. That is a weak fixture for the same
-- reason a verifier with one coarse arm is weak: the failure does not name itself.
--
-- `heikki@` is ACTIVE with NO local password, so the AUTH arm and the STATUS arm become INDEPENDENTLY
-- observable:
--
--   grace@   deactivated + no password  -> the two together
--   heikki@  ACTIVE      + no password  -> the AUTH arm alone
--   member@  ACTIVE      + password     -> the control
--
-- And `heikki@` is the row that proves the ruled AUTH label: no password in an org with NO sso_configs row is
-- NEITHER local nor SSO, so the cell must read "no local password" and stop there.
INSERT INTO users (id, email, name, password_hash, email_verified_at, status, created_at)
VALUES ('01900000-0000-7000-8000-0000000b0005', 'heikki@demo.tunnex.local', 'Heikki Laine',
        NULL, now() - interval '60 days', 'active', now() - interval '60 days')
ON CONFLICT (id) DO UPDATE
  SET status = EXCLUDED.status, email_verified_at = EXCLUDED.email_verified_at;

INSERT INTO memberships (org_id, user_id, role, created_at)
VALUES ('01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-0000000b0005',
        'member', now() - interval '60 days')
ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role;

-- ⛔ A MEMBER WITH NO NAME — AND THE FIXTURE'S ABSENCE OF ONE HID A LIVE RENDER DEFECT.
--
-- `users.name` is `NOT NULL DEFAULT ''` and `acceptInvitation`'s `name` is OPTIONAL, so anyone who accepts an
-- invite without supplying one has `''`. MEASURED: 144 of 241 users in this database have an empty name. It is
-- not a corner case; it is what an invite-driven org mostly looks like.
--
-- Every seeded member above has a name, so the roster cell rendered `{m.name || m.email}` AND `{m.email}`
-- unconditionally and NOBODY EVER SAW the address printed twice. A test MOCK that omitted `name` is what
-- surfaced it.
--
--   THE FIXTURE WAS LESS REPRESENTATIVE THAN THE DOUBLE. S14.10's trap was a double MORE PERMISSIVE than the
--   substrate; this is the same lesson from the other side, and only the fixture side is reviewable on a screen.
--
-- Named 'Nadia' in the EMAIL only — the name column stays empty deliberately. Do not "fix" it.
INSERT INTO users (id, email, name, password_hash, email_verified_at, status, created_at)
VALUES ('01900000-0000-7000-8000-0000000b0006', 'nadia-no-name@demo.tunnex.local', '',
        '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
        now() - interval '30 days', 'active', now() - interval '30 days')
ON CONFLICT (id) DO UPDATE
  SET name = EXCLUDED.name,   -- re-runnable INTO the state it describes: the empty name is the point
      status = EXCLUDED.status, email_verified_at = EXCLUDED.email_verified_at;

INSERT INTO memberships (org_id, user_id, role, created_at)
VALUES ('01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-0000000b0006',
        'member', now() - interval '30 days')
ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role;

-- ⛔ EMPTY NAME **AND** A LONG ADDRESS — the INTERACTION, seeded separately from the isolated case above.
--
-- One isolation per fact keeps `nadia-no-name@` about the empty name alone. But the original defect was a
-- DOUBLED STRING, and **truncation is where a doubled string hides**: a clipped second copy reads as one copy,
-- so a fix confirmed only at a short address is confirmed at the length least able to expose it.
--
-- Measured on the shipped cell: NO `truncate`, `overflow-hidden`, `whitespace-nowrap` or `text-ellipsis` on
-- either span, the `<td>`, or any ancestor up to the `<tr>` — so it wraps. A wiring test walks that ancestor
-- chain and was PROVEN to fire (adding `truncate` to the span reds it with `expected [ 'SPAN.truncate' ]`).
INSERT INTO users (id, email, name, password_hash, email_verified_at, status, created_at)
VALUES ('01900000-0000-7000-8000-0000000b0007',
        'oluwaseun.adebayo-contractor.external@a-very-long-subdomain.demo.tunnex.local', '',
        '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
        now() - interval '20 days', 'active', now() - interval '20 days')
ON CONFLICT (id) DO UPDATE
  SET name = EXCLUDED.name, status = EXCLUDED.status, email_verified_at = EXCLUDED.email_verified_at;

INSERT INTO memberships (org_id, user_id, role, created_at)
VALUES ('01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-0000000b0007',
        'member', now() - interval '20 days')
ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role;

-- ⛔ RULES 7-9 LIVE HERE, NOT WITH RULES 1-6, AND THE REASON IS A REAL BUG THIS ORDERING FIXES.
--
-- They reference `grace@` and `member@` via `src_user_id`, and those user rows are inserted FURTHER DOWN
-- this file. The `policy_rules` block above runs FIRST, so on a FRESH database the FK
-- `policy_rules_src_user_fk` fails:
--     insert or update on table "policy_rules" violates foreign key constraint (SQLSTATE 23503)
--
-- ⛔ IT PASSED ON THE PRIMARY STACK BECAUSE THOSE USERS ALREADY EXISTED FROM EARLIER SEEDS. The ordering was
-- wrong the whole time and invisible, because that database is months old and never re-created. The
-- OPEN-EDITION REVIEW STACK — a fresh DB — found it on its FIRST RUN, which is the argument for the second
-- stack restated as evidence: a long-lived database hides every ordering defect in the file that seeds it.
INSERT INTO policy_rules (id, org_id, src_kind, src_group_id, src_user_id, src_site_id, src_cidr, dst_kind, dst_resource_id, dst_group_id, dst_site_id, dst_k8s_service_id, disabled, expires_at, managed_by_machine, created_at)
VALUES
  -- ⛔ RULES 7-9 (S14.12 D3): THE THREE DISCRIMINATED-UNION ARMS THE FIXTURE NEVER PRODUCED.
  --
  -- `policy_rules` carries FOUR CHECK constraints, two of them discriminated unions:
  --     src_kind IN (group, user, site, cidr)      dst_kind IN (resource, group, site, k8s_service)
  -- Rules 1-6 covered 5 of those 8 arms. `src_kind='user'` (S7.5.4 per-user grants), `src_kind='site'` and
  -- `dst_kind='site'` (S8.2 site-to-site transit) had NO ROW — three SHIPPED features, CHECK-backed, that
  -- no screen has ever rendered.
  --
  --   A SCREEN RENDERING A DISCRIMINATED UNION CAN ONLY BE REVIEWED ON THE ARMS THE FIXTURE PRODUCES.
  --   The unrendered arms are exactly the ones that ship broken (S14.10: `posture blocked` had never
  --   rendered on localhost because the fixture aged out of the state it described).

  -- Rule 7: src_kind='user' — a PER-USER grant (S7.5.4). Grace is DEACTIVATED, so this row also asks the
  -- screen a second question: does a grant naming an account that cannot sign in render any differently?
  ('01900000-0000-7000-8000-000000080007', '01900000-0000-7000-8000-000000000001', 'user', NULL, '01900000-0000-7000-8000-0000000b0004', NULL, NULL, 'resource', '01900000-0000-7000-8000-000000090002', NULL, NULL, NULL, false, NULL, NULL, now() - interval '8 days'),

  -- Rule 8: src_kind='site' -> dst_kind='site' — SITE-TO-SITE TRANSIT (S8.2). Covers BOTH missing site arms
  -- in one row, which is deliberate: the two are the same feature and splitting them would seed a
  -- combination the product does not actually produce.
  ('01900000-0000-7000-8000-000000080008', '01900000-0000-7000-8000-000000000001', 'site', NULL, NULL, '01900000-0000-7000-8000-0000000e0002', NULL, 'site', NULL, NULL, '01900000-0000-7000-8000-0000000e0003', NULL, false, NULL, NULL, now() - interval '6 days'),

  -- Rule 9: src_kind='user' with an EXPIRY — the S7.5.4 TEMPORARY grant. `expires_at` is served and has no
  -- fixture row anywhere else, so the screen's expiry rendering is currently unreviewable.
  ('01900000-0000-7000-8000-000000080009', '01900000-0000-7000-8000-000000000001', 'user', NULL, '01900000-0000-7000-8000-000000000003', NULL, NULL, 'group', NULL, '01900000-0000-7000-8000-0000000a0001', NULL, NULL, false, now() + interval '3 days', NULL, now() - interval '1 day')
ON CONFLICT (id) DO NOTHING;

-- ⛔ AN EMPTY GROUP, AND A RULE THAT USES IT — the src_group_empty subject (S14.12).
--
-- All three seeded groups have members, so the fourth warn kind had NO SUBJECT and could only be seen by a
-- reviewer who remembered to create one by hand.
--
--   A STATE REACHABLE ONLY WHEN SOMEONE REMEMBERS TO CREATE IT IS NOT PERMANENTLY REVIEWABLE.
--
-- Same discipline as S14.10's `posture blocked`: the states that do not render are the ones that ship broken.
--
-- WHAT THIS SLICE ACTUALLY FIXED, and it is not the badge: UNTIL NOW, A NEW CUSTOMER'S FIRST TEN MINUTES
-- PRODUCED A RULE THAT SILENTLY GRANTED NOTHING. Create a group, write a rule against it, and the rule
-- compiled to nothing while rendering ACTIVE — because `matched = owner[r.SrcGroupID]` (compiler.go:399)
-- matches no device when the group has no members, and no surface existed to put anyone in it.
--
-- DO NOT "FIX" THIS BY ADDING A MEMBER. The emptiness is the fixture's purpose.
--
-- ⛔ AND THE EMPTINESS IS RE-ASSERTED ON EVERY SEED, NOT MERELY CREATED ONCE.
--
-- A reviewer exercised the new "Add a member" picker on THIS group during the S14.12 pass — the obvious thing
-- to try, on the one group that had an add control and no members — and the permanently-reviewable state was
-- gone in four seconds.
--
--   A REVIEWABLE STATE THAT ANYONE CAN DESTROY BY USING THE PRODUCT IS NOT PERMANENTLY REVIEWABLE.
--   Creating it once is not seeding it; the seed must be RE-RUNNABLE INTO the state it describes, which is
--   the same law the `ON CONFLICT DO UPDATE` class already carries for time-relative values.
--
-- Org-scoped by construction: the group id belongs to exactly one org.
DELETE FROM group_members WHERE group_id = '01900000-0000-7000-8000-0000000a0004';
INSERT INTO user_groups (id, org_id, name, description, origin, created_at, updated_at)
VALUES ('01900000-0000-7000-8000-0000000a0004', '01900000-0000-7000-8000-000000000001',
        'Interns', 'Seeded EMPTY on purpose: the src_group_empty subject. Do not add members.',
        'manual', now() - interval '4 days', now() - interval '4 days')
ON CONFLICT (id) DO UPDATE SET description = EXCLUDED.description;

-- The rule that consumes it. It renders ACTIVE and compiles to nothing — which is exactly what the badge
-- exists to say out loud.
INSERT INTO policy_rules (id, org_id, src_kind, src_group_id, src_user_id, src_site_id, src_cidr, dst_kind, dst_resource_id, dst_group_id, dst_site_id, dst_k8s_service_id, disabled, expires_at, managed_by_machine, created_at)
VALUES ('01900000-0000-7000-8000-00000008000a', '01900000-0000-7000-8000-000000000001',
        'group', '01900000-0000-7000-8000-0000000a0004', NULL, NULL, NULL,
        'resource', '01900000-0000-7000-8000-000000090001', NULL, NULL, NULL,
        false, NULL, NULL, now() - interval '3 days')
ON CONFLICT (id) DO NOTHING;

-- ⛔ SSO: ENTRA CONFIGURED, GOOGLE NOT — both arms of the panel in one org (S14.13 D2).
--
-- `sso_configs` was an unmeasured fixture ZERO, registered at S14.11: GET /sso/{provider} answered
-- 404 sso_not_configured for every provider, so the CONFIGURED render had never been seen on any stack.
-- That matters more than a missing state here: the S14.11 DESTRUCTIVE finding lives on this panel — a
-- non-`sso_not_configured` failure used to render the CONFIGURE form over an org that HAS SSO, inviting an
-- admin to reconfigure from scratch against a live IdP. UNREVIEWABLE without a configured org.
--
-- Entra configured / Google not, deliberately: both arms render side by side, so "configured" and
-- "not configured" are compared rather than toggled between.
--
-- `client_secret_sealed` is AES-GCM at rest and NEVER returned — the API serves only `secret_fingerprint`.
-- The bytes below are inert filler: nothing reads them back, and the fixture must not imply a real secret.
-- The FINGERPRINT is what the panel renders, so it is the field that must look truthful.
INSERT INTO sso_configs (id, org_id, provider, client_id, client_secret_sealed, secret_fingerprint, tenant_id, enabled, created_at, updated_at)
VALUES ('01900000-0000-7000-8000-000000060001', '01900000-0000-7000-8000-000000000001',
        'microsoft', 'acme-tunnex-prod', '\x00'::bytea, '3f9c2a71bd04',
        '72f9c1e4-0a3d-4b77-9d21-8e5a6f0b4c13', true,
        now() - interval '90 days', now() - interval '12 days')
ON CONFLICT (id) DO UPDATE
  SET client_id = EXCLUDED.client_id,
      secret_fingerprint = EXCLUDED.secret_fingerprint,
      tenant_id = EXCLUDED.tenant_id,
      enabled = EXCLUDED.enabled,
      updated_at = EXCLUDED.updated_at;

-- ⛔ GOOGLE IS DELIBERATELY ABSENT. Do not add it: the unconfigured arm is the state EVERY org passes
-- through, and it is the one the destructive fix must render correctly.

COMMIT;

-- ══════════════════════════════════════════════════════════════════════════════════════════════
-- S14.14 · DIRECTORY SYNC (IdP) — the second unmeasured fixture ZERO, same shape as sso_configs.
--
-- `idp_sync_configs` was empty on every stack, so GET …/idp-sync/{provider}/health answered
-- 404 idp_sync_not_configured for BOTH providers and the CONFIGURED arm — the health tiers, the
-- synced-group list, the un-map confirm — had never rendered anywhere. Five endpoints with no
-- call sites AND no data behind them is a surface nobody could review even after building it.
--
-- MICROSOFT: configured and DEGRADED ON PURPOSE. `last_sync_ok = false` with a RECENT
-- `last_sync_at` is what ClassifySyncHealth (enterprise/idpsync/health.go) projects as the
-- immediate tier: a poll is failing, but the last good sync is inside the 30-minute
-- EscalationCeiling. Set it further back than 30 minutes and this row renders ESCALATED instead
-- — the fixture is choosing WHICH tier is reviewable, so the interval is the load-bearing value.
-- GOOGLE: deliberately absent, so both arms show at once (the S14.13 SSO pattern that worked).
--
-- ⚠ secret_sealed is INERT FILLER. The real column holds a sealed blob and the API never returns
-- it; nothing in the UI reads it, so a fixture must not imply a usable credential exists. The
-- fields the panel actually renders (client_id, health, timestamps) are the ones made truthful.
INSERT INTO idp_sync_configs (id, org_id, provider, client_id, secret_sealed, tenant_id, enabled,
                              last_sync_at, last_sync_ok, last_sync_error, created_at, updated_at)
VALUES ('01900000-0000-7000-8000-000000070001', '01900000-0000-7000-8000-000000000001',
        'microsoft', 'acme-directory-sync', '\x00'::bytea,
        '72f9c1e4-0a3d-4b77-9d21-8e5a6f0b4c13', true,
        now() - interval '11 minutes', false,
        'directory request failed: 401 Unauthorized (client secret may have expired)',
        now() - interval '40 days', now() - interval '11 minutes')
ON CONFLICT (org_id, provider) DO UPDATE
  SET client_id       = EXCLUDED.client_id,
      tenant_id       = EXCLUDED.tenant_id,
      enabled         = EXCLUDED.enabled,
      last_sync_at    = EXCLUDED.last_sync_at,
      last_sync_ok    = EXCLUDED.last_sync_ok,
      last_sync_error = EXCLUDED.last_sync_error;
-- ⛔ DO NOT ADD A GOOGLE ROW. Its absence IS the not-configured arm.

-- A mapped group, so the synced-group list and the un-map confirm have a subject. origin and the
-- two idp_* columns move together — `user_groups_origin_shape` CHECKs exactly that, so a partial
-- fixture row would be rejected by the database rather than render a half-state.
INSERT INTO user_groups (id, org_id, name, description, origin, idp_provider, idp_group_id, created_at)
VALUES ('01900000-0000-7000-8000-0000000a0007', '01900000-0000-7000-8000-000000000001',
        'Directory · Engineering', 'Synced from Microsoft Entra', 'idp_sync',
        'microsoft', 'a3f1c7e0-9b24-4d5a-8e13-6c07f2b95d48', now() - interval '40 days')
ON CONFLICT (id) DO UPDATE
  SET origin = EXCLUDED.origin, idp_provider = EXCLUDED.idp_provider,
      idp_group_id = EXCLUDED.idp_group_id;

-- Two members, so un-mapping has something to destroy and the consequence list is not abstract.
INSERT INTO group_members (org_id, group_id, user_id, origin, created_at)
-- These two are real fixture members of the demo org: group_members carries a composite FK to
-- memberships(org_id, user_id), so a user who is not a member is REJECTED rather than orphaned.
VALUES ('01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-0000000a0007',
        '01900000-0000-7000-8000-000000000003', 'idp_sync', now() - interval '40 days'),
       ('01900000-0000-7000-8000-000000000001', '01900000-0000-7000-8000-0000000a0007',
        '01900000-0000-7000-8000-0000000b0005', 'idp_sync', now() - interval '40 days')
ON CONFLICT (group_id, user_id) DO NOTHING;

-- ══════════════════════════════════════════════════════════════════════════════════════════════
-- S14.15 · INVITATIONS — the third unmeasured fixture ZERO, and the one that mattered most.
--
-- `invitations` was empty on every stack, so the panel that finally makes resend/revoke reachable
-- had nothing to render. All FOUR lifecycle states are seeded, because the render derives them
-- from TIMESTAMPS and a clock rather than a status column — a fixture that only covered `pending`
-- would leave three of the four arms unexercised on the review stack.
--
-- ⛔ `expired` IS THE ONE A FIXTURE CAN GET WRONG SILENTLY: it is DERIVED (expires_at < now()),
-- never stored, so the interval below is load-bearing — move it forward and the row renders as
-- pending and the expired arm is never seen.
--
-- token_hash values are inert filler. The raw token is returned exactly once by createInvitation
-- and is NOT recoverable from a hash, so these cannot be redeemed — which is the point: a fixture
-- must not create an accepted-shaped invitation that anyone could actually use.
INSERT INTO invitations (id, org_id, email, role, token_hash, expires_at, accepted_at, revoked_at,
                         invited_by_user_id, created_at)
VALUES
  -- PENDING — the row resend/revoke exist for, and the one nobody could see before this story.
  ('01900000-0000-7000-8000-0000000c0001', '01900000-0000-7000-8000-000000000001',
   'priya.raman@acme.io', 'member', '\x01'::bytea, now() + interval '5 days',
   NULL, NULL, '01900000-0000-7000-8000-000000000002', now() - interval '2 days'),
  -- EXPIRED — pending in the database, expired only against the clock. Derived, not stored.
  ('01900000-0000-7000-8000-0000000c0002', '01900000-0000-7000-8000-000000000001',
   'stale.invite@acme.io', 'admin', '\x02'::bytea, now() - interval '3 days',
   NULL, NULL, '01900000-0000-7000-8000-000000000002', now() - interval '10 days'),
  -- ACCEPTED — proves the panel does not offer resend/revoke on a redeemed invitation.
  ('01900000-0000-7000-8000-0000000c0003', '01900000-0000-7000-8000-000000000001',
   'member@demo.tunnex.local', 'member', '\x03'::bytea, now() + interval '1 day',
   now() - interval '20 days', NULL, '01900000-0000-7000-8000-000000000002', now() - interval '25 days'),
  -- REVOKED — and deliberately NOT revoked by a human. SupersedePendingInvites clears pending
  -- invites when a user joins another way (domain-capture JIT), so an operator can meet a
  -- revocation they did not perform. The panel must not imply they did it.
  ('01900000-0000-7000-8000-0000000c0004', '01900000-0000-7000-8000-000000000001',
   'jit.joiner@acme.io', 'member', '\x04'::bytea, now() + interval '2 days',
   NULL, now() - interval '1 day', '01900000-0000-7000-8000-000000000002', now() - interval '6 days'),
  -- ⛔ INVITER GONE — invited_by_user_id is ON DELETE SET NULL, so this NULL is a state the
  -- product can really reach. The LEFT JOIN keeps the row; an inner join would DROP it, hiding an
  -- outstanding invitation precisely because its sender left.
  ('01900000-0000-7000-8000-0000000c0005', '01900000-0000-7000-8000-000000000001',
   'orphaned.invite@acme.io', 'member', '\x05'::bytea, now() + interval '4 days',
   NULL, NULL, NULL, now() - interval '4 days')
ON CONFLICT (id) DO UPDATE
  SET expires_at = EXCLUDED.expires_at, accepted_at = EXCLUDED.accepted_at,
      revoked_at = EXCLUDED.revoked_at, invited_by_user_id = EXCLUDED.invited_by_user_id;

-- ─────────────────────────────────────────────────────────────────────────────────────────────────
-- S15.1 — MACHINE CREDENTIAL OWNERSHIP. The states the assignment screen can render.
--
-- ⛔ WITHOUT THESE THE REVIEW IS BLIND. The screen was counted by this seeder and never seeded by it,
-- so a founder opening Settings saw an empty panel and learned nothing about the migration surface.
-- Per the Human Gate Limit Law, a screen review is only valid over what the data makes visible.
--
-- FOUR SEEDABLE STATES, deliberately in ONE org so the fleet is MIXED — which is itself a state: the
-- "all owned" banner must NOT render while any credential is unassigned.
--
--   1. unassigned + never seen      -> picker shown, "never seen"
--   2. unassigned + last seen       -> picker shown, "last seen <age>"   (the two renders differ, and
--                                      only the populated one had ever been looked at)
--   3. assigned  + last seen        -> owner rendered, NO picker
--   4. assigned  + never seen       -> owner rendered, NO picker, "never seen"
--
-- ⚠ token_hash is random and belongs to no issued token: these are DISPLAY fixtures. They can never
-- authenticate, which is correct — a seeded credential that worked would be a seeded backdoor.
INSERT INTO machine_credentials (id, org_id, name, role, token_hash, fingerprint, created_at, last_used_at, user_id)
VALUES
  ('019fd000-0000-7000-8000-00000000f001', '01900000-0000-7000-8000-000000000001',
   'gitops-prod',    'operator', sha256('fixture-gitops-prod'::bytea), 'fp-gitops-prod',
   now() - interval '21 days', NULL, NULL),
  ('019fd000-0000-7000-8000-00000000f002', '01900000-0000-7000-8000-000000000001',
   'gitops-staging', 'operator', sha256('fixture-gitops-staging'::bytea), 'fp-gitops-stag',
   now() - interval '9 days',  now() - interval '2 hours', NULL),
  ('019fd000-0000-7000-8000-00000000f003', '01900000-0000-7000-8000-000000000001',
   'ci-runner',      'operator', sha256('fixture-ci-runner'::bytea), 'fp-ci-runner',
   now() - interval '5 days',  now() - interval '11 minutes',
   (SELECT id FROM users WHERE email = 'owner@demo.tunnex.local')),
  ('019fd000-0000-7000-8000-00000000f004', '01900000-0000-7000-8000-000000000001',
   'backup-agent',   'operator', sha256('fixture-backup-agent'::bytea), 'fp-backup-agt',
   now() - interval '2 days',  NULL,
   (SELECT id FROM users WHERE email = 'owner@demo.tunnex.local'))
ON CONFLICT (id) DO NOTHING;

-- ─────────────────────────────────────────────────────────────────────────────────────────────────
-- S15.1 — THE ALL-OWNED ORG. The banner state, reachable FROM DATA.
--
-- ⛔ THE OTHER FOUR STATES LIVE IN THE DEMO ORG AND LEAVE TWO CREDENTIALS UNASSIGNED, SO THE
-- "every machine credential has an owner" BANNER IS UNREACHABLE THERE. The component computes it with
-- `creds.data.every(c => c.owner_user_id)`, so a single unassigned row suppresses it — which is correct,
-- and means a second SET in the same org cannot produce the state. It needs a second ORG.
--
-- ⚠ AND ASSIGNING THE TWO DEMO CREDENTIALS DURING THE REVIEW IS NOT A REVIEW OF THIS STATE. That exercises
-- the ASSIGNMENT FLOW — a different screen behaviour — and leaves the banner seen once, transiently, at the
-- end of an interaction rather than as the screen's own answer to "is the migration done".
--
-- The same owner as the demo org, so one login reaches both.
INSERT INTO organizations (id, name, slug, pool_cidr)
VALUES ('01900000-0000-7000-8000-0000000000a1', 'Demo EU', 'demo-eu', '10.98.0.0/24')
ON CONFLICT (id) DO NOTHING;

INSERT INTO memberships (id, org_id, user_id, role)
SELECT '01900000-0000-7000-8000-0000000000a2',
       '01900000-0000-7000-8000-0000000000a1',
       u.id, 'owner'
FROM users u WHERE u.email = 'owner@demo.tunnex.local'
ON CONFLICT DO NOTHING;

-- BOTH owned — so `.every()` is true and the banner renders from data.
-- ⚠ One with a last-seen and one never seen, so the banner is not accidentally coupled to that field.
INSERT INTO machine_credentials (id, org_id, name, role, token_hash, fingerprint, created_at, last_used_at, user_id)
SELECT v.id, '01900000-0000-7000-8000-0000000000a1', v.name, 'operator',
       sha256(('fixture-' || v.name)::bytea), v.fp, now() - v.age, v.seen,
       (SELECT id FROM users WHERE email = 'owner@demo.tunnex.local')
FROM (VALUES
  ('01900000-0000-7000-8000-0000000000b1'::uuid, 'gitops-eu',  'fp-gitops-eu',  interval '30 days', now() - interval '6 minutes'),
  ('01900000-0000-7000-8000-0000000000b2'::uuid, 'backup-eu',  'fp-backup-eu',  interval '12 days', NULL)
) AS v(id, name, fp, age, seen)
ON CONFLICT (id) DO NOTHING;

-- ─────────────────────────────────────────────────────────────────────────────────────────────────
-- S15.3 — THE AI-AGENT SURFACE. **WRITTEN BY HAND, PER STATE, WITH THE ABSENCES FIRST-CLASS.**
--
-- ⛔ THE STATES THAT MATTER MOST ON THIS SCREEN ARE ABSENCES: an agent with NO OWNER (unattributable), an
-- agent with NO ADDRESS, an agent with NO REACHABLE DESTINATIONS. A generator that filled every field would
-- erase exactly the states the screen exists to show — which is the keyless-OVPN-device regression again,
-- one story later, and the reason these rows are typed out rather than looped.
--
-- ⚠ AND "REACHABLE" MEANS REACHABLE IN THE PRODUCT. S15.1 seeded a state into an org with no switcher and
-- the coverage count said 5 of 5 while four were visible. Every row below is in the DEMO org, which the
-- reviewer lands on by default.
-- ─────────────────────────────────────────────────────────────────────────────────────────────────

-- ⚠ A DEDICATED USER FOR THE DEPARTED-OWNER STATE. Using an existing fixture member and deleting their
-- membership would disturb the Users screen; this user exists only to leave. The membership is created and
-- then removed, which is exactly how the state arises in life: the person was a member when they authorised
-- the agent, and is not one now.
INSERT INTO users (id, email, name, email_verified_at)
VALUES ('01900000-0000-7000-8000-00000000b001', 'departed@demo.tunnex.local', 'Dana (left the org)', now())
ON CONFLICT (id) DO NOTHING;
DELETE FROM memberships WHERE user_id = '01900000-0000-7000-8000-00000000b001';

-- Two agent gateways. Both are real `nodes` rows so the surface's node-half resolves.
INSERT INTO nodes (id, org_id, name, cert_serial, agent_version, owner_user_id)
VALUES
  -- STATE 1 — the healthy case: owned, addressed, attributable.
  ('01900000-0000-7000-8000-00000000a001', '01900000-0000-7000-8000-000000000001',
   'mcp-agent-prod', 'fixture-serial-ag001', '1.4.0',
   (SELECT id FROM users WHERE email = 'owner@demo.tunnex.local')),
  -- ⛔ STATE 2 — THE OWNER WHO LEFT THE ORG. The node keeps its recorded owner (the join token's issuer),
  -- and that person is no longer a member. `owner_email` resolves from `users`, which survives the
  -- membership going away (S15.1/D22) — so the agent stays ATTRIBUTABLE and the screen can still name who
  -- authorised it. This is the degraded state the product can ACTUALLY reach.
  --
  -- ⚠ THE STATE THIS REPLACED WAS IMPOSSIBLE, AND THE FIXTURE WAS THE ONLY PLACE IT COULD EXIST. It set
  -- `nodes.owner_user_id = NULL` while giving the agent a device row — and `allocateAgentDevice` runs only
  -- when the token carries an issuer, setting NODE and DEVICE owner to the SAME person. An unowned agent
  -- gets no device row at all. The fixture manufactured a contradiction the product cannot produce, and it
  -- rendered as two opposite claims about one device on one screen.
  ('01900000-0000-7000-8000-00000000a002', '01900000-0000-7000-8000-000000000001',
   'mcp-agent-departed', 'fixture-serial-ag002', '1.2.0',
   '01900000-0000-7000-8000-00000000b001')
ON CONFLICT (id) DO NOTHING;

-- The agent device rows — `kind='agent'`, which is what makes the surface recognise them.
--
-- ⚠ THE KEYS ARE THE PLACEHOLDER SHAPE ON PURPOSE. An agent's device row is an ATTRIBUTION identity, not a
-- WireGuard peer: the agent IS the gateway and does not peer with itself. The peer-set query excludes these
-- by format (S15.2 walk Leg 4), and that exclusion is correct — seeding a real key here would make the
-- fixture claim something the product does not do.
INSERT INTO devices (id, org_id, user_id, node_id, name, platform, public_key, assigned_ip, status, kind, transport)
VALUES
  ('01900000-0000-7000-8000-00000000d001', '01900000-0000-7000-8000-000000000001',
   (SELECT id FROM users WHERE email = 'owner@demo.tunnex.local'),
   '01900000-0000-7000-8000-00000000a001', 'mcp-agent-prod', 'agent',
   'pending-agent-01900000-0000-7000-8000-00000000a001', '10.99.0.31', 'active', 'agent', 'wireguard'),
  -- ⛔ STATE 3 — NO ADDRESS. An agent whose /32 allocation did not land cannot be named in a flow event at
  -- all. The screen must render "no address" rather than hiding the row or inventing one.
  -- ⚠ THE DEVICE'S USER IS THE NODE'S OWNER, because the product sets both from the SAME issuer. Setting
  -- them independently is what produced two contradictory claims about one device.
  ('01900000-0000-7000-8000-00000000d002', '01900000-0000-7000-8000-000000000001',
   '01900000-0000-7000-8000-00000000b001',
   '01900000-0000-7000-8000-00000000a002', 'mcp-agent-departed', 'agent',
   'pending-agent-01900000-0000-7000-8000-00000000a002', NULL, 'active', 'agent', 'wireguard')
ON CONFLICT (id) DO NOTHING;

-- ⛔ STATE 4 — A LABELLED DESTINATION, AND STATE 5 — AN UNLABELLED ONE.
-- The label is an OPERATOR'S ASSERTION, never an inference: the product cannot detect that something speaks
-- MCP. Seeding one labelled and one bare is what makes that visible — a screen where every resource carried
-- a label could not show that the field is optional and human-supplied.
INSERT INTO resources (id, org_id, name, cidr, protocol, port_low, port_high, label)
VALUES
  ('01900000-0000-7000-8000-00000000c001', '01900000-0000-7000-8000-000000000001',
   'internal-mcp', '10.20.7.10/32', 'tcp', 8931, 8931, 'MCP server'),
  ('01900000-0000-7000-8000-00000000c002', '01900000-0000-7000-8000-000000000001',
   'metrics-scrape', '10.20.7.11/32', 'tcp', 9090, 9090, NULL)
ON CONFLICT (id) DO NOTHING;

-- ⚠ STATE 6 — AN AGENT WITH NO REACHABLE DESTINATIONS is `mcp-agent-legacy`: NO grant references it, and
-- that absence is deliberate. It is not a gap in the fixture; it is the state an operator most needs to
-- recognise — an agent that exists, runs, and can reach nothing.


-- ⛔ AND THE STATE THAT IS NOT SEEDED, DECLARED RATHER THAN OMITTED: **UNATTRIBUTABLE**.
--
-- An agent with no owner is UNREACHABLE IN THE PRODUCT'S OWN DATA MODEL, and the reason is structural:
-- `allocateAgentDevice` runs only when the join token carries an issuer, so an unowned agent gets NO
-- `kind='agent'` device row — and with no agent row it is **indistinguishable from a plain gateway**.
--
-- > **THE SCREEN'S MOST IMPORTANT STATE CANNOT OCCUR.** The renderer handles it (agentview.ts, tested), so
-- > the surface is correct if the state ever arrives — but nothing can currently produce it, and a fixture
-- > that faked it was manufacturing a contradiction rather than exercising a path.
--
-- ⚠ SUBSTITUTE: the unit tests in `apps/web/test/agentview.test.ts` cover the unattributable rendering and
-- its sort order. NAMED TRIGGER: whenever a node gains an agent marker independent of its device row — the
-- decide-item registered from S15.3.
-- The grant below makes `mcp-agent-prod` reach a labelled destination, so the screen has one agent that
-- reaches something and one that reaches nothing.
INSERT INTO policy_rules (id, org_id, src_kind, src_user_id, dst_kind, dst_resource_id)
SELECT '01900000-0000-7000-8000-00000000e001', '01900000-0000-7000-8000-000000000001',
       'user', (SELECT id FROM users WHERE email = 'owner@demo.tunnex.local'),
       'resource', '01900000-0000-7000-8000-00000000c001'
WHERE EXISTS (SELECT 1 FROM resources WHERE id = '01900000-0000-7000-8000-00000000c001')
ON CONFLICT (id) DO NOTHING;
