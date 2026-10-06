#!/bin/sh
# Synthetic-only recovery: aa0 contributes DDL only, never private row data/keys.
set -eu
umask 077
cd "$(dirname "$0")"
nonce=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
source="sa_recovery_source_$nonce"
destination="sa_recovery_dest_$nonce"
case "$source" in sa_recovery_source_????????????) ;; *) exit 1 ;; esac
case "$destination" in sa_recovery_dest_????????????) ;; *) exit 1 ;; esac
mkdir -p .runtime/recovery
schema=.runtime/recovery/synthetic-schema.sql
archive=.runtime/bin/recovery-fixture.dump
./run.sh exec -T postgres pg_dump -U aa0 -d aa0 --schema-only --no-owner --no-privileges > "$schema"
./run.sh exec -T postgres createdb -U aa0 "$source"
./run.sh exec -T postgres psql -X -v ON_ERROR_STOP=1 -U aa0 -d "$source" < "$schema" >/dev/null
archive_schema=$(./run.sh exec -T postgres psql -X -At -U aa0 -d "$source" -c "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='server_access_settings' AND column_name='archive_enabled')")
if [ "$archive_schema" = f ]; then ./run.sh exec -T postgres psql -X -v ON_ERROR_STOP=1 -U aa0 -d "$source" < ../../apps/api/db/migrations/0203_server_access_recording_archive.up.sql >/dev/null; fi
./run.sh exec -T -e TUNNEX_SA_RECOVERY_TEST=1 -e "TUNNEX_SA_RECOVERY_SOURCE=$source" -e "TUNNEX_SA_RECOVERY_DB=$source" -e TUNNEX_SA_RECOVERY_PHASE=seed api /binaries/recovery-agent-tests -test.run '^TestRecoveryOwnedSnapshot$' -test.v
# Full dumps are permitted only for our newly seeded synthetic namespace.
./run.sh exec -T postgres pg_dump -U aa0 -d "$source" -Fc --no-owner --no-privileges > "$archive"
chmod 600 "$archive"
./run.sh exec -T -e TUNNEX_SA_RECOVERY_TEST=1 -e "TUNNEX_SA_RECOVERY_SOURCE=$source" -e "TUNNEX_SA_RECOVERY_DB=$destination" -e TUNNEX_SA_RECOVERY_PHASE=verify api /binaries/recovery-agent-tests -test.run '^TestRecoveryOwnedSnapshot$' -test.v
./run.sh exec -T api cat "/tmp/$destination.backup.enc" > ".runtime/recovery/$destination.backup.enc"
chmod 600 ".runtime/recovery/$destination.backup.enc"
./run.sh exec -T postgres createdb -U aa0 "$destination"
./run.sh exec -T postgres pg_restore -U aa0 -d "$destination" --no-owner --no-privileges < "$archive"
./run.sh exec -T -e TUNNEX_SA_RECOVERY_TEST=1 -e "TUNNEX_SA_RECOVERY_SOURCE=$source" -e "TUNNEX_SA_RECOVERY_DB=$destination" api /binaries/recovery-agent-tests -test.run '^TestRecoveryOwnedSnapshot$' -test.v
./run.sh exec -T -e TUNNEX_SA_RECOVERY_TEST=1 -e "TUNNEX_SA_RECOVERY_SOURCE=$source" -e "TUNNEX_SA_RECOVERY_DB=$destination" api /binaries/recovery-agent-tests -test.run '^TestRecoveryOwnedEnvelopeMigration$' -test.v
printf 'Synthetic source and restored target retained: %s %s\nEncrypted synthetic backup mode0600; actual installation master/data never copied.\n' "$source" "$destination"
