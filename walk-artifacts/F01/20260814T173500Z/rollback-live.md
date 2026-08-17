# F01 disposable migration rollback walk

Date: 2026-08-14 UTC
Project: `f01-rollback-20260814` only
Database: PostgreSQL 16 in the disposable compose volume
Redaction: fixture IDs are stable synthetic IDs; no credentials or live data were used.

## Setup

The fresh project migrated three isolated databases through the current repository tip:

```text
defaultdb     migrate_up_complete version=83 dirty=false
nondefaultdb  migrate_up_complete version=83 dirty=false
suspendeddb   migrate_up_complete version=83 dirty=false
```

Each database contained one synthetic organization, user, gateway, active agent device, and default agent profile. The non-default case changed profile metadata to `environment=prod`, `runtime=python`, `labels={"team":"sec"}`. The suspended case changed only the canonical device status to `suspended`; profile metadata remained default `{}`.

## Default profile: successful 0079 down

The disposable migration tool ran down from 83 through 78:

```text
83 -> 82 dirty=false
82 -> 81 dirty=false
81 -> 80 dirty=false
80 -> 79 dirty=false
79 -> 78 dirty=false
```

Post-rollback assertions:

```text
schema_migrations: 78|false
device row count for synthetic agent: 1
agent_profiles table absent: true
```

The device row survived with its canonical identity/status data. No profile or device value was discarded.

## Non-default metadata: refusal and preservation

The database reached `79|dirty=false` after rolling back 0083, 0082, 0081, and 0080. The 0079 down command exited `1` with:

```text
0079 rollback refused: non-default agent profile metadata would be lost
```

After refusal:

```text
schema_migrations: 78|dirty=true
device status: active
profile: prod|python|{"team": "sec"}
```

The migration was marked dirty by the migration runner, but the guard ran before destructive statements: `agent_profiles` and every captured value remained present.

## Suspended device: refusal and preservation

The database reached `79|dirty=false` after rolling back 0083, 0082, 0081, and 0080. The 0079 down command exited `1` with:

```text
0079 rollback refused: suspended agent/device rows must be resumed or revoked first
```

After refusal:

```text
schema_migrations: 78|dirty=true
device status: suspended
profile: ||{}
```

The suspended device and its default profile remained intact. No destructive rollback step ran.

## Cleanup

`docker compose -p f01-rollback-20260814 down -v` removed only the disposable project’s PostgreSQL volume, container, and network. Follow-up volume/network listing showed no `f01-rollback-20260814` resources. The retained `f01-browser` project and all other stacks were not touched.

This satisfies the live rollback gate. The connected-agent suspend→peer/config absence→resume data-plane gate remains open; F01 remains In Progress.
