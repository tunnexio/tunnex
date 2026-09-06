import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
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
  assert.equal(jobs.api.strategy['fail-fast'], false);
  assert.match(jobs.api.env.COMPOSE_PROJECT_NAME, /matrix.edition/);
  for (const name of ['api', 'tooling']) {
    assert.equal(jobs[name].if, "needs.scope.outputs.go == 'true'");
  }
  assert.equal(jobs.codegen.if, "needs.scope.outputs.codegen == 'true'");
  assert.equal(jobs.web.if, undefined);
  assert.ok(jobs.web.steps.some(step => !step.if && /tsc --noEmit/.test(step.run ?? '')));
  for (const name of ['scope', 'contracts', 'codegen', 'api', 'tooling', 'web', 'gates']) {
    assert.notEqual(jobs[name]['continue-on-error'], true);
    for (const step of jobs[name].steps) assert.notEqual(step['continue-on-error'], true);
  }
  const makefile = readFileSync('Makefile', 'utf8');
  assert.match(makefile, /go test -count=1 -p 1/);
  assert.match(makefile, /GO_DOCKER_CACHE.*\/go\/pkg\/mod.*\/root\/\.cache\/go-build/);
  for (const [name, lane] of [['api', 'edition'], ['tooling', 'target']]) {
    const cache = jobs[name].steps.find(step =>
      step.uses === './.github/actions/go-container-cache');
    assert.equal(cache.with.lane, '${{ matrix.' + lane + ' }}');
  }
  const cacheAction = readFileSync('.github/actions/go-container-cache/action.yml', 'utf8');
  assert.equal((cacheAction.match(/inputs\.lane/g) ?? []).length, 2,
    'both exact key and restore prefix must isolate matrix cache writers');
});
