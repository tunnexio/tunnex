import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { validateGates } from './ci-gates.mjs';

const full = () => Object.fromEntries(
  ['scope', 'contracts', 'codegen', 'api', 'app-access-integration', 'tooling', 'web'].map(name => [
    name, { result: 'success', ...(name === 'scope' ? {
      outputs: { go: 'true', web: 'true', codegen: 'true', docs_only: 'false' },
    } : {}) },
  ]),
);
test('full run succeeds only with all lanes successful', () => {
  assert.deepEqual(validateGates(full()), []);
});
for (const lane of Object.keys(full())) {
  for (const result of ['failure', 'cancelled', 'skipped', '', 'unknown']) {
    test(`rejects ${lane} ${result || 'empty'}`, () => {
      const needs = full();
      needs[lane].result = result;
      assert.ok(validateGates(needs).length);
    });
  }
  test(`rejects missing ${lane}`, () => {
    const needs = full();
    delete needs[lane];
    assert.ok(validateGates(needs).length);
  });
}
test('all valid classification combinations preserve conditional skips', () => {
  for (const go of ['true', 'false']) for (const web of ['true', 'false']) {
    for (const codegen of ['true', 'false']) {
      const needs = full();
      Object.assign(needs.scope.outputs, { go, web, codegen });
      if (go === 'false') needs.api.result = needs['app-access-integration'].result = needs.tooling.result = 'skipped';
      if (codegen === 'false') needs.codegen.result = 'skipped';
      assert.deepEqual(validateGates(needs), []);
    }
  }
});
test('docs-only still requires contracts and E2E spec compilation', () => {
  const needs = full();
  needs.scope.outputs = { go: 'false', web: 'false', codegen: 'false', docs_only: 'true' };
  for (const key of ['api', 'app-access-integration', 'tooling', 'codegen']) needs[key].result = 'skipped';
  assert.deepEqual(validateGates(needs), []);
  needs.web.result = 'skipped';
  assert.ok(validateGates(needs).length);
});
test('rejects malformed or inconsistent classification', () => {
  assert.ok(validateGates(null).length);
  for (const key of ['go', 'web', 'codegen', 'docs_only']) {
    const needs = full();
    delete needs.scope.outputs[key];
    assert.ok(validateGates(needs).length);
  }
  const needs = full();
  needs.scope.outputs.docs_only = 'true';
  assert.ok(validateGates(needs).length);
});
test('CLI exits nonzero for malformed input and failed jobs', () => {
  for (const input of ['not json', '{}', JSON.stringify({ scope: { result: 'failure' } })]) {
    const result = spawnSync(process.execPath, ['deploy/ci-gates.mjs'], {
      env: { ...process.env, GATE_NEEDS: input },
    });
    assert.equal(result.status, 1);
  }
});
test('workflow graph and cache wiring enforce the tested boundary', () => {
  const parsed = spawnSync('ruby', ['-ryaml', '-rjson', '-e',
    'puts JSON.generate(YAML.load_file(ARGV[0]))', '.github/workflows/ci.yml'], { encoding: 'utf8' });
  assert.equal(parsed.status, 0, parsed.stderr);
  const { jobs } = JSON.parse(parsed.stdout);
  assert.deepEqual([...jobs.gates.needs].sort(), Object.keys(full()).sort());
  assert.equal(jobs.gates.if, 'always()');
  assert.ok(jobs.gates.steps.some(step => step.run === 'node deploy/ci-gates.mjs' &&
    step.env.GATE_NEEDS === '${{ toJSON(needs) }}'));
  assert.deepEqual(jobs.api.strategy.matrix.edition, ['open', 'enterprise']);
  assert.deepEqual(jobs.api.strategy.matrix.shard, ['db', 'ipsec', 'nodes', 'other']);
  assert.match(jobs.api.env.COMPOSE_PROJECT_NAME, /matrix.shard/);
  assert.match(jobs.api.env.GATE_CACHE_PREFIX, /matrix.shard/);
  assert.ok(jobs.api.steps.some(s => /API_TEST_SHARD=\$\{\{ matrix.shard \}\}/.test(s.run ?? '')));
  assert.equal(jobs.api.strategy['fail-fast'], false);
  assert.match(jobs.api.env.COMPOSE_PROJECT_NAME, /matrix.edition/);
  assert.ok(jobs.tooling.strategy.matrix.target.includes('test-sandbox-package'));
  for (const name of ['api', 'app-access-integration', 'tooling']) {
    assert.equal(jobs[name].if, "needs.scope.outputs.go == 'true'");
  }
  assert.equal(jobs.codegen.if, "needs.scope.outputs.codegen == 'true'");
  assert.equal(jobs.web.if, undefined);
  assert.ok(jobs.web.steps.some(step => !step.if && /tsc --noEmit/.test(step.run ?? '')));
  for (const name of ['scope', 'contracts', 'codegen', 'api', 'app-access-integration', 'tooling', 'web', 'gates']) {
    assert.equal(jobs[name].steps.find(step => /^actions\/checkout@[0-9a-f]{40}$/.test(step.uses ?? ''))
      .with['fetch-depth'], 0, `${name} must preserve historical regression inputs`);
    assert.notEqual(jobs[name]['continue-on-error'], true);
    for (const step of jobs[name].steps) assert.notEqual(step['continue-on-error'], true);
  }
  const makefile = readFileSync('Makefile', 'utf8');
  assert.match(readFileSync('deploy/test-api-edition.sh', 'utf8'), /go test -count=1 -p 1/);
  assert.match(makefile, /API_TEST_SHARD/);
  assert.match(makefile, /sh \/repo\/deploy\/test-api-edition.sh/);
  assert.match(makefile, /GO_DOCKER_CACHE.*\/go\/pkg\/mod.*\/root\/\.cache\/go-build/);
  for (const [name, lane] of [['api', 'edition'], ['tooling', 'target']]) {
    const cache = jobs[name].steps.find(step =>
      step.uses === './.github/actions/go-container-cache');
    assert.equal(cache.with.lane, name === 'api' ? '${{ matrix.edition }}-${{ matrix.shard }}' : '${{ matrix.' + lane + ' }}');
  }
  const cacheAction = readFileSync('.github/actions/go-container-cache/action.yml', 'utf8');
  assert.equal((cacheAction.match(/inputs\.lane/g) ?? []).length, 2,
    'both exact key and restore prefix must isolate matrix cache writers');
});

test('sandbox bundles reuse blocking tooling and existing guarded release publication', () => {
  const parsed = spawnSync('ruby', ['-ryaml', '-rjson', '-e',
    'puts JSON.generate(YAML.load_file(ARGV[0]))', '.github/workflows/ci.yml'], { encoding: 'utf8' });
  assert.equal(parsed.status, 0, parsed.stderr);
  const { jobs } = JSON.parse(parsed.stdout);
  const upload = jobs.tooling.steps.find(step => step.name?.startsWith('Retain public Linux sandbox'));
  assert.ok(upload.if.includes("matrix.target == 'test-sandbox-package'"));
  assert.ok(upload.if.includes("github.ref == 'refs/heads/main'"));
  assert.ok(upload.if.includes("startsWith(github.ref, 'refs/tags/v')"));
  assert.equal(upload.with.name, 'tunnex-linux-sandbox');
  assert.equal(upload.with['if-no-files-found'], 'error');
  assert.deepEqual(upload.with.path.trim().split('\n'), [
    'dist/sandbox/amd64/tunnex-sandbox-linux-amd64.tar.gz',
    'dist/sandbox/amd64/tunnex-sandbox-linux-amd64.tar.gz.sha256',
    'dist/sandbox/arm64/tunnex-sandbox-linux-arm64.tar.gz',
    'dist/sandbox/arm64/tunnex-sandbox-linux-arm64.tar.gz.sha256',
  ]);
  const release = jobs['release-assets'];
  assert.ok(release.needs.includes('tooling'));
  const attachment = release.steps.find(step => step.name?.startsWith('Attach verified public sandbox'));
  assert.match(attachment.run, /package\.py verify .*--source "\$GITHUB_SHA"/);
  assert.match(attachment.run, /test "\$\(gh api .* --jq \.sha\)" = "\$GITHUB_SHA"/);
  assert.match(attachment.run, /--json isDraft --jq \.isDraft/);
  assert.match(attachment.run, /test "\$ACTUAL" = "\$EXPECTED"/);
  assert.equal((attachment.run.match(/sandbox-artifacts\/(?:amd64|arm64)\/tunnex-sandbox-linux-/g) ?? []).length, 4);
  assert.ok(release.steps.some(step => step.name === 'Attest public sandbox source bundles'));
  const contracts = jobs.contracts.steps.find(step => step.name?.startsWith('Sandbox public packaging'));
  for (const directory of ['deploy/sandbox', 'deploy/sandbox/qualification', 'deploy/sandbox/ci', 'deploy/sandbox/install']) {
    assert.ok(contracts.run.includes(`unittest discover -s ${directory} -p 'test_*.py'`));
  }
  const makefile = readFileSync('Makefile', 'utf8');
  assert.match(makefile, /^test-sandbox-package:/m);
  assert.match(makefile, /package\.py build --arch amd64/);
  assert.match(makefile, /package\.py build --arch arm64/);
  assert.match(makefile, /unittest discover -s deploy\/sandbox\/install/);
});


for (const [workflow, stepId, expected] of [
  ['ci', 'scope', { go: 'true', web: 'true', codegen: 'true', docs_only: 'false' }],
  ['security', 'c', { go: 'true', javascript: 'true' }],
]) test(`${workflow} large PR classification drains input and retains required lanes`, (t) => {
  const parsed = spawnSync('ruby', ['-ryaml', '-rjson', '-e',
    'puts JSON.generate(YAML.load_file(ARGV[0]))', `.github/workflows/${workflow}.yml`], { encoding: 'utf8' });
  assert.equal(parsed.status, 0, parsed.stderr);
  const { jobs } = JSON.parse(parsed.stdout);
  const classify = jobs.scope.steps.find(step => step.id === stepId).run
    .replaceAll('${{ github.event_name }}', 'pull_request')
    .replaceAll('${{ github.event.pull_request.base.sha }}', 'fixture-base');
  const dir = mkdtempSync(join(tmpdir(), 'tunnex-ci-scope-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const output = join(dir, 'outputs');
  const fakeGit = `git() {
    if [ "$1" = "cat-file" ]; then return 0; fi
    if [ "$1" != "diff" ]; then return 1; fi
    case "$*" in *--diff-filter=D*) return 0;; esac
    printf '%s\n' apps/api/internal/fixture.go apps/web/src/fixture.tsx
    for n in {1..10000}; do printf 'docs/large-publication-fixture-%s.md\n' "$n"; done
  }
`;
  const result = spawnSync('bash', ['-c', fakeGit + classify], {
    encoding: 'utf8', env: { ...process.env, GITHUB_OUTPUT: output },
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const values = Object.fromEntries(readFileSync(output, 'utf8').trim().split('\n').map(line => line.split('=')));
  assert.deepEqual(values, expected);
});

test('integration lanes run alongside unit gates but publication still requires all gates', () => {
  const parsed = spawnSync('ruby', ['-ryaml', '-rjson', '-e',
    'puts JSON.generate(YAML.load_file(ARGV[0]))', '.github/workflows/ci.yml'], { encoding: 'utf8' });
  assert.equal(parsed.status, 0, parsed.stderr);
  const { jobs } = JSON.parse(parsed.stdout);
  for (const name of ['e2e', 'e2e-enterprise', 'visual']) {
    assert.equal(jobs[name].needs, 'scope');
    assert.equal(jobs[name].if, "always() && needs.scope.outputs.docs_only != 'true'");
  }
  for (const name of ['release-version-guard', 'publish']) {
    for (const gate of ['gates', 'e2e', 'e2e-enterprise']) {
      assert.ok(jobs[name].needs.includes(gate));
      assert.ok(jobs[name].if.includes(`needs.${gate}.result == 'success'`));
    }
  }
  const operator = jobs['operator-build'];
  assert.equal(operator.needs, 'scope');
  assert.ok(operator.if.includes("github.event_name == 'pull_request'"));
  assert.deepEqual(operator.strategy.matrix.arch, ['amd64', 'arm64']);
  assert.ok(!operator.steps.some(step => /setup-qemu/.test(step.uses ?? '')));
  const build = operator.steps.find(step => step.id === 'build').with;
  assert.equal(build.push, false);
  assert.equal(build.platforms, 'linux/${{ matrix.arch }}');
  assert.equal(build.file, 'apps/operator/Dockerfile');
});

test('API test runner edits select both edition test lanes', t => {
  const parsed = spawnSync('ruby', ['-ryaml', '-rjson', '-e',
    'puts JSON.generate(YAML.load_file(ARGV[0]))', '.github/workflows/ci.yml'], { encoding: 'utf8' });
  assert.equal(parsed.status, 0, parsed.stderr);
  const classify = JSON.parse(parsed.stdout).jobs.scope.steps.find(s => s.id === 'scope').run
    .replaceAll('${{ github.event_name }}', 'pull_request')
    .replaceAll('${{ github.event.pull_request.base.sha }}', 'fixture-base');
  const dir = mkdtempSync(join(tmpdir(), 'api-shard-scope-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const output = join(dir, 'outputs');
  const result = spawnSync('bash', ['-c', `git() {
    [ "$1" != cat-file ] || return 0
    case "$*" in *--diff-filter=D*) return 0;; esac
    printf '%s\\n' deploy/test-api-edition.sh
  }
` + classify], { encoding: 'utf8', env: { ...process.env, GITHUB_OUTPUT: output } });
  assert.equal(result.status, 0, result.stderr);
  assert.match(readFileSync(output, 'utf8'), /^go=true$/m);
  assert.match(readFileSync(output, 'utf8'), /^docs_only=false$/m);
});

test('sandbox recipe, package and installer assets select the blocking tooling lane', t => {
  const parsed = spawnSync('ruby', ['-ryaml', '-rjson', '-e',
    'puts JSON.generate(YAML.load_file(ARGV[0]))', '.github/workflows/ci.yml'], { encoding: 'utf8' });
  assert.equal(parsed.status, 0, parsed.stderr);
  const classify = JSON.parse(parsed.stdout).jobs.scope.steps.find(s => s.id === 'scope').run
    .replaceAll('${{ github.event_name }}', 'pull_request')
    .replaceAll('${{ github.event.pull_request.base.sha }}', 'fixture-base');
  const dir = mkdtempSync(join(tmpdir(), 'sandbox-package-scope-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const file of ['deploy/sandbox/Containerfile', 'deploy/sandbox/ci/package.py', 'deploy/sandbox/install/example.json']) {
    const output = join(dir, 'outputs');
    const result = spawnSync('bash', ['-c', `git() {
      [ "$1" != cat-file ] || return 0
      case "$*" in *--diff-filter=D*) return 0;; esac
      printf '%s\\n' ${file}
    }
` + classify], { encoding: 'utf8', env: { ...process.env, GITHUB_OUTPUT: output } });
    assert.equal(result.status, 0, result.stderr);
    assert.match(readFileSync(output, 'utf8'), /^go=true$/m, file);
    assert.match(readFileSync(output, 'utf8'), /^docs_only=false$/m, file);
    writeFileSync(output, '');
  }
});

test('node lane requires the unprivileged Unix fixture before root nft and full-suite checks', () => {
  const makefile = readFileSync('Makefile', 'utf8');
  const nodeRecipe = makefile.match(/^test-node:[\s\S]*?(?=^\.PHONY:|\Z)/m)?.[0];
  assert.ok(nodeRecipe);
  assert.match(nodeRecipe, /--cap-add=NET_ADMIN/);
  assert.match(nodeRecipe, /go test -c -o \/tmp\/sandboxnetwork\.test \.\/internal\/sandboxnetwork &&/);
  assert.match(nodeRecipe, /su -s \/bin\/sh nobody -c "\/tmp\/sandboxnetwork\.test -test\.run \^TestInactiveCleanupActualUnixBoundary\$\$ -test\.v" &&/);
  assert.ok(nodeRecipe.indexOf('su -s /bin/sh nobody') < nodeRecipe.indexOf('go test -count=1 ./...'));
  assert.doesNotMatch(nodeRecipe, /\|\| true|continue-on-error/);
});

test('App Access integration owns its services and cannot pass on skipped evidence', (t) => {
  const parsed = spawnSync('ruby', ['-ryaml', '-rjson', '-e',
    'puts JSON.generate(YAML.load_file(ARGV[0]))', '.github/workflows/ci.yml'], { encoding: 'utf8' });
  assert.equal(parsed.status, 0, parsed.stderr);
  const job = JSON.parse(parsed.stdout).jobs['app-access-integration'];
  assert.deepEqual(job.strategy.matrix.edition, ['open', 'enterprise']);
  assert.equal(job.strategy['fail-fast'], false);
  assert.equal(job.env.APP_ACCESS_LOCAL_INTEGRATION, '1');
  assert.equal(job.env.GOFLAGS, '-mod=readonly');
  assert.deepEqual(Object.keys(job.services).sort(), ['postgres', 'redis']);
  for (const service of Object.values(job.services)) {
    assert.equal(service.ports, undefined, 'fixture service must not publish host ports');
    assert.equal(service.volumes, undefined, 'fixture service must not reuse external data');
  }
  const scripts = job.steps.map(step => step.run ?? '').join('\n');
  assert.doesNotMatch(scripts, /make migrate|seed-fixtures|FLUSHALL|docker (?:system|volume) prune/);
  assert.match(scripts, /cmp app-access-ci\/parent-before\.txt app-access-ci\/parent-after\.txt/);
  assert.match(scripts, /go test -json -count=1 -p=1 .*\.\/internal\/appaccess/);
  assert.match(scripts, /TestAppParentLogoutLocalIntegration\|TestAppParentPasswordReplacementLocalIntegration\|TestNativeSSOConfigRestoreLocalDatabase/);
  assert.match(scripts, /\^TestNewAtVersionPreservesParentSchema\$/);
  assert.ok(job.steps.find(step => step.name?.startsWith('Require actual test')).if.startsWith('always()'));
  assert.match(readFileSync('Makefile', 'utf8'), /^SQLC_IMAGE \?= sqlc\/sqlc:1\.31\.1$/m);
  assert.match(readFileSync('Makefile', 'utf8'), /-w \/src \$\(SQLC_IMAGE\) generate/);

  // Execute the real workflow evidence verifier with synthetic event streams:
  // exit0 alone, a missing test, a skipped subtest or malformed JSON must fail.
  const verification = job.steps.find(step => step.name?.startsWith('Require actual test')).run;
  const code = verification.match(/python3 - <<'PY'\n([\s\S]*?)\nPY(?:\n|$)/)?.[1];
  assert.ok(code, 'workflow JSON verifier must remain exercised');
  const dir = mkdtempSync(join(tmpdir(), 'app-access-ci-evidence-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const out = join(dir, 'app-access-ci');
  mkdirSync(out);
  writeFileSync(join(out, 'expected-tests.json'), JSON.stringify(['TestOwnedFeature']));
  const suites = {
    appaccess: ['TestOwnedFeature'],
    'http-authority': ['TestAppParentLogoutLocalIntegration', 'TestAppParentPasswordReplacementLocalIntegration', 'TestNativeSSOConfigRestoreLocalDatabase'],
    testpostgres: ['TestNewAtVersionPreservesParentSchema'],
  };
  const success = names => [...names.map(Test => ({ Action: 'pass', Test })), { Action: 'pass' }];
  const write = (name, rows) => writeFileSync(join(out, `${name}.jsonl`), rows.map(row => JSON.stringify(row)).join('\n') + '\n');
  const reset = () => Object.entries(suites).forEach(([name, names]) => write(name, success(names)));
  const run = () => spawnSync('python3', ['-c', code], { cwd: dir, encoding: 'utf8' });
  reset();
  assert.equal(run().status, 0);
  assert.equal(JSON.parse(readFileSync(join(out, 'result.json'), 'utf8')).appaccess.functional_skips, 0);
  for (const name of Object.keys(suites)) {
    reset();
    write(name, [{ Action: 'pass' }]);
    assert.notEqual(run().status, 0, `${name}: package pass without expected tests`);
    reset();
    write(name, [...success(suites[name]), { Action: 'skip', Test: `${suites[name][0]}/missing fixture` }]);
    assert.notEqual(run().status, 0, `${name}: functional subtest skipped`);
    reset();
    write(name, [...success(suites[name]), { Action: 'fail' }]);
    assert.notEqual(run().status, 0, `${name}: package failure`);
    reset();
    writeFileSync(join(out, `${name}.jsonl`), 'not JSON\n');
    assert.notEqual(run().status, 0, `${name}: invalid evidence`);
  }
});


test('App Access shipping contracts run after Helm with an explicit isolated YAML dependency', () => {
  const parsed = spawnSync('ruby', ['-ryaml', '-rjson', '-e',
    'puts JSON.generate(YAML.load_file(ARGV[0]))', '.github/workflows/ci.yml'], { encoding: 'utf8' });
  assert.equal(parsed.status, 0, parsed.stderr);
  const steps = JSON.parse(parsed.stdout).jobs.contracts.steps;
  const helm = steps.findIndex(step => step.uses?.startsWith('azure/setup-helm@'));
  const index = steps.findIndex(step => step.name === 'App Access packaging, restore and upgrade contracts');
  assert.ok(helm >= 0 && index > helm, 'shipping contracts require the pinned Helm setup');
  const step = steps[index];
  assert.equal(step.if, undefined, 'shipping guards must not be silently conditional');
  assert.equal(step['timeout-minutes'], 5);
  assert.notEqual(step['continue-on-error'], true);
  assert.match(step.run, /python3 -m venv/);
  assert.match(step.run, /\$RUNNER_TEMP\/app-access-contracts/);
  assert.match(step.run, /pip install --disable-pip-version-check 'PyYAML==6\.0\.2'/);
  assert.match(step.run, /-B -m unittest discover -s deploy\/app-access\/tests -p 'test_\*\.py' -v/);
  assert.ok(step.run.indexOf('pip install') < step.run.indexOf('unittest discover'));
  assert.doesNotMatch(step.run, /docker|kubectl|helm (?:install|upgrade)/);
});
