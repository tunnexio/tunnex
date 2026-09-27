import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { validateGates } from './ci-gates.mjs';

const full = () => Object.fromEntries(
  ['scope', 'contracts', 'codegen', 'api', 'tooling', 'web'].map(name => [
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
      if (go === 'false') needs.api.result = needs.tooling.result = 'skipped';
      if (codegen === 'false') needs.codegen.result = 'skipped';
      assert.deepEqual(validateGates(needs), []);
    }
  }
});
test('docs-only still requires contracts and E2E spec compilation', () => {
  const needs = full();
  needs.scope.outputs = { go: 'false', web: 'false', codegen: 'false', docs_only: 'true' };
  for (const key of ['api', 'tooling', 'codegen']) needs[key].result = 'skipped';
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
  for (const name of ['api', 'tooling']) {
    assert.equal(jobs[name].if, "needs.scope.outputs.go == 'true'");
  }
  assert.equal(jobs.codegen.if, "needs.scope.outputs.codegen == 'true'");
  assert.equal(jobs.web.if, undefined);
  assert.ok(jobs.web.steps.some(step => !step.if && /tsc --noEmit/.test(step.run ?? '')));
  for (const name of ['scope', 'contracts', 'codegen', 'api', 'tooling', 'web', 'gates']) {
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
