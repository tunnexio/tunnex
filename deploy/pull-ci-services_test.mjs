import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
for (const failures of [0, 1, 2, 3]) test(`registry download with ${failures} failures`, t => {
  const dir = mkdtempSync(join(tmpdir(), 'ci-pull-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'docker'), `#!/bin/sh
printf '%s\\n' "$*" >> "$CALLS"
n=$(wc -l < "$CALLS")
[ "$n" -gt "$FAILURES" ] || exit 7
`, { mode: 0o755 });
  writeFileSync(join(dir, 'sleep'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  const r = spawnSync('sh', [resolve('deploy/pull-ci-services.sh'), 'postgres', 'redis'], {
    env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, CALLS: join(dir, 'calls'), FAILURES: String(failures) }, encoding: 'utf8',
  });
  assert.equal(r.status, failures === 3 ? 7 : 0, r.stderr);
  assert.deepEqual(readFileSync(join(dir, 'calls'), 'utf8').trim().split('\n'),
    Array(Math.min(failures + 1, 3)).fill('compose pull postgres redis'));
});
