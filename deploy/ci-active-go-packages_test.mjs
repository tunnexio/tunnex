import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const roots = Object.fromEntries(['api', 'node', 'cli'].map(module => [module, `github.com/tunnexio/tunnex/apps/${module}`]));
function run(t, module, packages, flags = [], fail = '') {
  const dir = mkdtempSync(join(tmpdir(), 'shelved-main-active-go-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'go'), `#!/bin/sh
printf '%s\\n' "$*" >> "$CALLS"
printf '%s\\n' "$GOFLAGS" > "$FLAGS"
[ "$1" != "$FAIL" ] || exit 9
if [ "$1" = list ]; then printf '%s\\n' "$PACKAGES"; fi
`, { mode: 0o755 });
  const result = spawnSync('sh', [resolve('deploy/ci-active-go-packages.sh'), module, ...flags], {
    encoding: 'utf8', env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, GOFLAGS: '-trimpath',
      FAIL: fail, PACKAGES: packages.join('\n'), CALLS: join(dir, 'calls'), FLAGS: join(dir, 'flags') },
  });
  let calls = []; try { calls = readFileSync(join(dir, 'calls'), 'utf8').trim().split('\n'); } catch {}
  let goflags = ''; try { goflags = readFileSync(join(dir, 'flags'), 'utf8').trim(); } catch {}
  return { ...result, calls, goflags };
}
const inventory = {
  api: {
    active: ['', 'db', 'internal/http', 'internal/devices', 'internal/policy', 'internal/nodes', 'internal/gatewaymesh', 'internal/bootstrap', 'internal/sandboxproduct', 'internal/sandboxruntime-new', 'internal/future', 'cmd/server'],
    dormant: ['internal/sandboxes', 'internal/sandboxes/nested', 'internal/sandboxrunner', 'internal/sandboxruntime', 'internal/sandboxscope', 'cmd/tunnex-sandbox-runtime', 'cmd/tunnex-sandbox-future'],
  },
  node: {
    active: ['', 'cmd/agent', 'internal/reconcile', 'internal/policy', 'internal/openvpn', 'internal/sandboxproduct', 'internal/future', 'internal/sandboxnetworked'],
    dormant: ['internal/sandboxnetwork', 'internal/sandboxnetwork/nested', 'cmd/tunnex-sandbox-network', 'cmd/tunnex-sandbox-future'],
  },
  cli: {
    active: ['', 'cmd/tunnex', 'internal/cli', 'internal/api', 'internal/future', 'cmd/tunnex-sandbox-future'],
    dormant: ['cmd/tunnex-sandbox-bootstrap'],
  },
};
for (const [module, expected] of Object.entries(inventory)) {
  const path = name => name ? `${roots[module]}/${name}` : roots[module];
  test(`${module}: shared, guard and unknown packages remain active`, t => {
    const active = expected.active.map(path);
    const r = run(t, module, [...active, ...expected.dormant.map(path)]);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(r.stdout.trim().split('\n'), active);
    assert.deepEqual(r.calls, ['list ./...']);
    assert.equal(r.goflags, '-trimpath -mod=readonly');
  });
  test(`${module}: dormant-only discovery cannot pass an empty test lane`, t => {
    const r = run(t, module, expected.dormant.map(path));
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /empty active Go package selection/);
  });
}
test('enterprise discovery tags and failures propagate', t => {
  const r = run(t, 'api', [`${roots.api}/internal/http`], ['-tags', 'enterprise']);
  assert.equal(r.status, 0); assert.deepEqual(r.calls, ['list -tags enterprise ./...']);
  const failed = run(t, 'api', [`${roots.api}/internal/http`], ['-tags', 'enterprise'], 'list');
  assert.equal(failed.status, 9); assert.equal(failed.stdout, '');
});
test('invalid module or package inventories fail before test selection', t => {
  const unknown = run(t, 'unknown', []);
  assert.notEqual(unknown.status, 0); assert.deepEqual(unknown.calls, []);
  for (const list of [[], ['foreign/module'], [`${roots.api}/internal/http extra`]]) {
    const r = run(t, 'api', list);
    assert.notEqual(r.status, 0); assert.equal(r.stdout, '');
  }
});
test('standard Make lanes preserve compilation, CLI vet and native VPN tools', () => {
  for (const [target, module] of [['test-node', 'node'], ['test-cli', 'cli'], ['e2e', 'api']]) {
    const r = spawnSync('make', ['-n', target, 'PG_USER=fixture', 'PG_PASS=fixture', 'PG_DB=fixture', 'NET=fixture'], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /go build \.\/\.\.\./);
    assert.ok(r.stdout.includes(`ci-active-go-packages.sh ${module}`));
    assert.doesNotMatch(r.stdout, /sandboxnetwork\.test|su -s \/bin\/sh nobody/);
    if (target === 'test-node') {
      assert.match(r.stdout, /--cap-add=NET_ADMIN/);
      assert.match(r.stdout, /apk add --no-cache git openvpn nftables iptables/);
    }
    if (target === 'test-cli') assert.match(r.stdout, /go vet \.\/\.\.\./);
    if (target === 'e2e') {
      assert.match(r.stdout, /apk add --no-cache python3/);
      assert.match(r.stdout, /go test -p 1 \$packages/);
    }
  }
  const makefile = readFileSync('Makefile', 'utf8');
  const transport = makefile.match(/^test-apptransport:[\s\S]*?(?=^\.PHONY:)/m)?.[0];
  assert.match(transport, /go test -count=1 \.\/\.\.\./);
  assert.doesNotMatch(transport, /ci-active-go-packages/);
});
test('sandbox Make compatibility checks invoke no build tools', t => {
  const dir = mkdtempSync(join(tmpdir(), 'shelved-main-make-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const tool of ['docker', 'python3', 'go']) writeFileSync(join(dir, tool), '#!/bin/sh\nexit 9\n', { mode: 0o755 });
  const r = spawnSync('make', ['-s', 'test-sandbox-package', 'test-sandbox-image', 'PG_USER=fixture', 'PG_PASS=fixture', 'PG_DB=fixture', 'NET=fixture'], {
    encoding: 'utf8', env: { ...process.env, PATH: `${dir}:${process.env.PATH}` },
  });
  assert.equal(r.status, 0, r.stderr);
  assert.equal((r.stdout.match(/SHELVED:/g) ?? []).length, 2);
  assert.match(r.stdout, /no checks or artifacts ran/);
  assert.equal(r.stderr, '');
});
