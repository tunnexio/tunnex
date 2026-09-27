import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
const root = 'github.com/tunnexio/tunnex/apps/api';
const packages = ['db', 'db/sqlc', 'internal/ipsec', 'internal/nodes', 'internal/http', 'internal/new-feature', 'cmd/api'].map(p => `${root}/${p}`);
function run(t, shard, edition = 'open', fail = '', list = packages) {
  const dir = mkdtempSync(join(tmpdir(), 'api-shard-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'go'), `#!/bin/sh
printf '%s\\n' "$*" >> "$CALLS"
[ "$1" != "$FAIL" ] || exit 9
if [ "$1" = list ]; then printf '%s\\n' "$PACKAGES"; fi
`, { mode: 0o755 });
  const result = spawnSync('sh', [resolve('deploy/test-api-edition.sh')], {
    encoding: 'utf8', env: { ...process.env, PATH: `${dir}:${process.env.PATH}`,
      TEST_EDITION: edition, API_TEST_SHARD: shard, FAIL: fail,
      PACKAGES: list.join('\n'), CALLS: join(dir, 'calls'), TUNNEX_TEST_DATABASE_URL: 'postgres://fixture/isolated' },
  });
  let calls = []; try { calls = readFileSync(join(dir, 'calls'), 'utf8').trim().split('\n'); } catch {}
  return { ...result, calls };
}
for (const edition of ['open', 'enterprise']) {
  test(`${edition}: shards cover every package exactly once, including future packages`, t => {
    const seen = [];
    for (const shard of ['db', 'ipsec', 'nodes', 'other']) {
      const r = run(t, shard, edition);
      assert.equal(r.status, 0, r.stderr);
      const tags = edition === 'enterprise' ? ' -tags enterprise' : '';
      assert.equal(r.calls[0], `build${tags} ./...`);
      assert.equal(r.calls[1], `list${tags} ./...`);
      assert.ok(r.calls[2].startsWith(`test -count=1 -p 1${tags} `));
      seen.push(...r.calls[2].split(' ').filter(s => s.startsWith(root)));
    }
    assert.deepEqual(seen.sort(), [...packages].sort());
    assert.equal(new Set(seen).size, packages.length);
    const all = run(t, 'all', edition);
    assert.equal(all.status, 0);
    assert.deepEqual(all.calls[2].split(' ').filter(s => s.startsWith(root)), packages);
  });
}
for (const fail of ['build', 'list', 'test']) test(`propagates ${fail} failure`, t => {
  const r = run(t, 'other', 'open', fail);
  assert.equal(r.status, 9);
  assert.equal(r.calls.length, { build: 1, list: 2, test: 3 }[fail]);
});
test('refuses unknown edition or shard before running Go', t => {
  for (const [shard, edition] of [['oops', 'open'], ['db', 'oops']]) {
    const r = run(t, shard, edition); assert.notEqual(r.status, 0); assert.deepEqual(r.calls, []);
  }
});
test('empty or renamed dedicated shard cannot silently pass', t => {
  const r = run(t, 'ipsec', 'open', '', [`${root}/internal/new-ipsec`]);
  assert.notEqual(r.status, 0); assert.equal(r.calls.length, 2);
});
