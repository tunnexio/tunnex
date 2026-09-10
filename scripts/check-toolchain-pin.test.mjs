import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

const root = resolve(import.meta.dirname, '..');
const files = execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' })
  .trim().split('\n').filter((path) =>
    /^apps\/[^/]+\/go\.mod$/.test(path) ||
    /^apps\/[^/]+\/Dockerfile$/.test(path) ||
    /^deploy\/docker\/[^/]+\.Dockerfile$/.test(path) ||
    ['Makefile', '.devcontainer/devcontainer.json', 'scripts/check-toolchain-pin.sh'].includes(path));

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'tunnex-toolchain-contract-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const file of files) {
    mkdirSync(dirname(join(dir, file)), { recursive: true });
    cpSync(join(root, file), join(dir, file));
  }
  return dir;
}
function check(dir) {
  return spawnSync('bash', ['scripts/check-toolchain-pin.sh'], { cwd: dir, encoding: 'utf8' });
}
function replace(dir, file, before, after) {
  const path = join(dir, file);
  const source = readFileSync(path, 'utf8');
  assert.ok(source.includes(before));
  writeFileSync(path, source.replace(before, after));
}

test('first-party and immutable upstream pins both pass', (t) => {
  const result = check(fixture(t));
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
test('upstream builder drift remains blocking', (t) => {
  const dir = fixture(t);
  replace(dir, 'apps/ai-engine/Dockerfile', 'golang:1.27.0', 'golang:1.26.0');
  const result = check(dir);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /requires pinned upstream Go 1\.27\.0/);
});
test('first-party module drift remains blocking', (t) => {
  const dir = fixture(t);
  const original = readFileSync(join(dir, 'apps/api/go.mod'), 'utf8').match(/^go (\S+)/m)[0];
  replace(dir, 'apps/api/go.mod', original, 'go 1.0.0');
  const result = check(dir);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /MISMATCH/);
});
test('other Docker builders cannot opt into the upstream exception', (t) => {
  const dir = fixture(t);
  const file = 'deploy/docker/api.Dockerfile';
  const original = readFileSync(join(dir, file), 'utf8').match(/golang:[^-\s]+/)[0];
  replace(dir, file, original, 'golang:1.27.0');
  const result = check(dir);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /MISMATCH.*deploy\/docker\/api\.Dockerfile/);
});
