import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { summarizeSarif } from './check-codeql-sarif.mjs';

const script = resolve(import.meta.dirname, 'check-codeql-sarif.mjs');
const descriptor = (id, severity, extra = {}) => ({ id, ...(severity === undefined ? {} : {
  properties: { tags: ['security'], 'security-severity': severity },
}), ...extra });
const sarif = (rules, results, extensions = []) => ({ version: '2.1.0', runs: [{
  tool: { driver: { name: 'CodeQL', rules }, extensions }, results,
}] });
const result = (extra = {}) => ({ ruleId: 'js/file-system-race', ruleIndex: 0, level: 'warning', ...extra });
const counts = (blocking, highCritical = blocking, errorLevel = 0) => ({ highCritical, errorLevel, blocking });
function cli(t, logs) {
  const dir = mkdtempSync(join(tmpdir(), 'codeql-severity-gate-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const files = logs.map((log, i) => {
    const file = join(dir, `${i}.sarif`);
    writeFileSync(file, typeof log === 'string' ? log : JSON.stringify(log));
    return file;
  });
  return spawnSync(process.execPath, [script, ...files], { encoding: 'utf8' });
}

test('High warning is blocked even though the previous error-only gate counted zero', (t) => {
  const log = sarif([descriptor('js/file-system-race', '7.7')], [result()]);
  assert.equal(log.runs[0].results.filter((finding) => finding.level === 'error').length, 0);
  assert.deepEqual(summarizeSarif(log), counts(1));
  const checked = cli(t, [log]);
  assert.equal(checked.status, 1);
  assert.match(checked.stdout, /1 high\/critical/);
});

test('Medium and Low warnings pass; the exact High and Critical boundaries block', () => {
  for (const [severity, blocking] of [['0.0', 0], ['3.9', 0], ['6.9', 0], ['7.0', 1], [9, 1], ['9.8', 1], [10, 1]]) {
    assert.deepEqual(summarizeSarif(sarif([descriptor('js/file-system-race', severity)], [result()])), counts(blocking));
  }
});

test('Critical findings block even with no result level or a note level', () => {
  for (const level of [undefined, 'note']) {
    const finding = { ruleId: 'critical', ...(level === undefined ? {} : { level }) };
    assert.deepEqual(summarizeSarif(sarif([descriptor('critical', '9.8')], [finding])), counts(1));
  }
});

test('Known nonsecurity warnings pass and explicit error-level blocking is preserved', () => {
  const rule = descriptor('correctness', undefined);
  assert.deepEqual(summarizeSarif(sarif([rule], [{ ruleId: 'correctness', level: 'warning' }])), counts(0));
  assert.deepEqual(summarizeSarif(sarif([rule], [{ ruleId: 'correctness', level: 'error' }])), counts(1, 0, 1));
  assert.deepEqual(summarizeSarif(sarif([descriptor('medium', '5.0')], [{ ruleId: 'medium', level: 'error' }])), counts(1, 0, 1));
  assert.deepEqual(summarizeSarif(sarif([descriptor('high', '7.0')], [{ ruleId: 'high', level: 'error' }])), counts(1, 1, 1));
});

test('Driver metadata resolves by rule ID, index, or a consistent descriptor reference', () => {
  for (const finding of [result({ ruleIndex: undefined }), { ruleIndex: 0 },
    { rule: { id: 'js/file-system-race', index: 0 } }, result({ rule: { id: 'js/file-system-race', index: 0 } })]) {
    assert.deepEqual(summarizeSarif(sarif([descriptor('js/file-system-race', '7.7')], [finding])), counts(1));
  }
});

test('CodeQL query-pack extension index zero does not address the driver', () => {
  const extensions = [{ name: 'codeql/javascript-queries', rules: [descriptor('js/file-system-race', '7.7')] }];
  const finding = { ruleId: 'js/file-system-race', level: 'warning', rule: {
    id: 'js/file-system-race', index: 0, toolComponent: { index: 0 },
  } };
  assert.deepEqual(summarizeSarif(sarif([descriptor('driver-rule', '1.0')], [finding], extensions)), counts(1));
});

test('Extension aliases and GUID selectors resolve within the selected component', () => {
  const extensions = [
    { name: 'other-pack', guid: 'other-guid', rules: [descriptor('same', '1.0')] },
    { name: 'security-pack', guid: 'security-guid', rules: [descriptor('same', '7.7', { guid: 'rule-guid' })] },
  ];
  for (const toolComponent of [{ index: 1, name: 'security-pack', guid: 'security-guid' }, { guid: 'security-guid' }]) {
    const finding = { ruleId: 'same', ruleIndex: 0, level: 'warning', rule: { guid: 'rule-guid', toolComponent } };
    assert.deepEqual(summarizeSarif(sarif([], [finding], extensions)), counts(1));
  }
  assert.deepEqual(summarizeSarif(sarif([], [{ rule: { guid: 'rule-guid', toolComponent: { index: 1 } } }], extensions)), counts(1));
});

test('One hierarchical result ID suffix uses its exact parent descriptor', () => {
  assert.deepEqual(summarizeSarif(sarif([descriptor('parent', '7.7')], [{ ruleId: 'parent/child', ruleIndex: 0 }])), counts(1));
  for (const ruleId of ['parentish', 'parent/', 'parent/child/grandchild']) {
    assert.throws(() => summarizeSarif(sarif([descriptor('parent', '7.7')], [{ ruleId, ruleIndex: 0 }])));
  }
});

test('Missing, conflicting, ambiguous and out-of-bounds rule metadata fail closed', () => {
  const rules = [descriptor('high', '7.7'), descriptor('medium', '5.0')];
  for (const finding of [{}, { ruleId: 'missing' }, { ruleIndex: -1 }, { ruleIndex: 100 },
    { ruleIndex: '0' }, { ruleIndex: null }, { ruleId: 'high', rule: null },
    { ruleId: 'high', rule: { id: null } }, { ruleId: 'high', rule: { index: null } }, { ruleId: 'high', ruleIndex: 1 },
    { ruleId: 'high', rule: { id: 'medium', index: 1 } }, { ruleIndex: 0, rule: { index: 1 } },
    { rule: { index: 0, guid: 'unknown' } }, { ruleId: 'high', rule: { index: 0, toolComponent: { index: 0 } } }]) {
    assert.throws(() => summarizeSarif(sarif(rules, [finding])));
  }
  assert.throws(() => summarizeSarif(sarif([descriptor('same', '1.0'), descriptor('same', '7.7')], [{ ruleId: 'same' }])));
});

test('Conflicting extension selectors cannot hide a High rule', () => {
  const extensions = [{ name: 'pack', guid: 'pack-guid', rules: [descriptor('high', '7.7')] }];
  for (const selector of [{ index: -1 }, { index: 1 }, { index: 0, guid: 'wrong' },
    { index: 0, name: 'wrong' }, { name: 'pack' }, { guid: 'missing' }]) {
    assert.throws(() => summarizeSarif(sarif([], [{ rule: { id: 'high', index: 0, toolComponent: selector } }], extensions)));
  }
});

test('Invalid security scores and missing security-tagged severity fail closed', () => {
  for (const severity of ['', 'NaN', 'Infinity', '7foo', null, true, -1, 11, {}, ' 7.7 ']) {
    assert.throws(() => summarizeSarif(sarif([descriptor('high', severity)], [{ ruleId: 'high' }])));
  }
  assert.throws(() => summarizeSarif(sarif([{ id: 'high', properties: { tags: ['security'] } }], [{ ruleId: 'high' }])));
  for (const tags of ['security', null, ['security', 1]]) {
    assert.throws(() => summarizeSarif(sarif([{ id: 'high', properties: { tags } }], [{ ruleId: 'high' }])));
  }
});

test('Multiple files and runs aggregate findings and a clean complete scan passes', (t) => {
  const clean = sarif([descriptor('medium', '6.9')], [{ ruleId: 'medium', level: 'warning' }]);
  assert.equal(cli(t, [clean, sarif([], [])]).status, 0);
  const high = sarif([descriptor('high', '7.7')], [{ ruleId: 'high', level: 'warning' }]);
  high.runs.push(structuredClone(high.runs[0]));
  assert.equal(cli(t, [clean, high]).status, 1);
  assert.deepEqual(summarizeSarif(high), counts(2));
});

test('Missing or malformed SARIF and empty runs fail rather than masquerading as a clean scan', (t) => {
  assert.equal(cli(t, []).status, 1);
  assert.equal(spawnSync(process.execPath, [script, '/does/not/exist.sarif']).status, 1);
  const nullResults = sarif([], []);
  nullResults.runs[0].results = null;
  for (const log of ['', '{}', '{"version":"2.1.0","runs":[]}', 'not json', { version: '2.1.0', runs: [{}] }, nullResults]) {
    assert.equal(cli(t, [log]).status, 1);
  }
});

test('The workflow consumes the tested severity helper under its existing analysis condition', () => {
  const workflow = readFileSync(resolve(import.meta.dirname, '../.github/workflows/security.yml'), 'utf8');
  assert.match(workflow, /node scripts\/check-codeql-sarif\.mjs "\$\{files\[@\]\}"/);
  assert.doesNotMatch(workflow, /select\(\.level == "error"\)/);
  assert.match(workflow, /queries: security-extended/);
});
