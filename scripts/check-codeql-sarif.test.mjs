import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { checkFiles, fetchGitHubReview, summarizeSarif } from './check-codeql-sarif.mjs';

const script = resolve(import.meta.dirname, 'check-codeql-sarif.mjs');
const descriptor = (id, severity, extra = {}) => ({ id, ...(severity === undefined ? {} : {
  properties: { tags: ['security'], 'security-severity': severity },
}), ...extra });
const sarif = (rules, results, extensions = []) => ({ version: '2.1.0', runs: [{
  tool: { driver: { name: 'CodeQL', rules }, extensions }, results,
}] });
const result = (extra = {}) => ({ ruleId: 'js/file-system-race', ruleIndex: 0, level: 'warning', ...extra });
const counts = (blocking, highCritical = blocking, errorLevel = 0, reviewedFalsePositives = 0) => ({ highCritical, errorLevel, reviewedFalsePositives, blocking });
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

test('Blocking output identifies rules, severities and locations without source or messages', (t) => {
  const log = sarif([descriptor('medium', '5.0'), descriptor('correctness', undefined)], [
    { rule: { id: 'go/example-high', index: 0, toolComponent: { index: 0 } }, level: 'warning',
      message: { text: 'MESSAGE_SECRET' }, locations: [{ physicalLocation: {
        artifactLocation: { index: 0 }, region: { startLine: 42, snippet: { text: 'SOURCE_SECRET' } },
      } }] },
    { ruleId: 'medium', level: 'warning' },
    { ruleId: 'correctness', level: 'error', locations: [{ physicalLocation: {
      artifactLocation: { uri: 'src/other.go' }, region: { startLine: 9 },
    } }] },
  ], [{ name: 'go-pack', rules: [descriptor('go/example-high', '7.7')] }]);
  log.runs[0].artifacts = [{ location: { uri: 'src/file%20name.go' } }];
  const checked = cli(t, [log]);
  assert.equal(checked.status, 1);
  const diagnostics = checked.stdout.split('\n').filter((line) => line.startsWith('blocking result: '))
    .map((line) => JSON.parse(line.slice('blocking result: '.length)));
  assert.deepEqual(diagnostics, [
    { ruleId: 'go/example-high', securitySeverity: 'high', securityScore: 7.7,
      resultLevel: 'warning', path: 'src/file name.go', line: 42 },
    { ruleId: 'correctness', securitySeverity: null, securityScore: null,
      resultLevel: 'error', path: 'src/other.go', line: 9 },
  ]);
  assert.doesNotMatch(checked.stdout + checked.stderr, /MESSAGE_SECRET|SOURCE_SECRET/);
  assert.match(checked.stdout, /blocking findings: 2/);
});

test('Missing or unsafe diagnostic locations do not hide blocking results or expose URI credentials', (t) => {
  const log = sarif([descriptor('critical', '9.8')], [
    { ruleIndex: 0, locations: [{ physicalLocation: { artifactLocation: {
      uri: 'https://user:URI_SECRET@example.test/source.go?token=URI_SECRET',
    }, region: { startLine: 4 } } }] },
    { ruleIndex: 0 },
  ]);
  const checked = cli(t, [log]);
  assert.equal(checked.status, 1);
  const diagnostics = checked.stdout.split('\n').filter((line) => line.startsWith('blocking result: '))
    .map((line) => JSON.parse(line.slice('blocking result: '.length)));
  assert.equal(diagnostics.length, 2);
  assert.ok(diagnostics.every((finding) => finding.ruleId === 'critical' && finding.securitySeverity === 'critical' && finding.path === null));
  assert.equal(diagnostics[1].line, null);
  assert.doesNotMatch(checked.stdout + checked.stderr, /URI_SECRET|example\.test/);
  assert.match(checked.stdout, /blocking findings: 2/);
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
  assert.match(workflow, /node scripts\/check-codeql-sarif\.mjs --github-dismissals "\$\{files\[@\]\}"/);
  assert.doesNotMatch(workflow, /select\(\.level == "error"\)/);
  assert.match(workflow, /queries: security-extended/);
  assert.match(workflow, /source-root: \./);
  assert.match(workflow, /CODEQL_ANALYSIS_SOURCE_ROOT: \$\{\{ github\.workspace \}\}/);
});

const githubContext = {
  repository: 'owner/repository', ref: 'refs/pull/10/merge', sha: 'a'.repeat(40),
  category: '/language:go', analysisKey: '.github/workflows/security.yml:codeql',
};
function reviewedFixture() {
  const finding = { ruleId: 'high', level: 'warning', locations: [{ physicalLocation: {
    artifactLocation: { uri: 'src/proxy.go' }, region: { startLine: 10, startColumn: 3, endLine: 10, endColumn: 9 },
  } }] };
  const log = sarif([descriptor('high', '7.7')], [finding]);
  log.runs[0].automationDetails = { id: '/language:go/' };
  log.runs[0].versionControlProvenance = [{ repositoryUri: 'https://github.com/owner/repository', revisionId: githubContext.sha }];
  const alert = { number: 1, rule: { id: 'high' }, tool: { name: 'CodeQL' },
    state: 'dismissed', dismissed_reason: 'false positive', most_recent_instance: {
      state: 'dismissed', ref: githubContext.ref, commit_sha: githubContext.sha,
      category: githubContext.category, analysis_key: githubContext.analysisKey,
      location: { path: 'src/proxy.go', start_line: 10, end_line: 10, start_column: 3, end_column: 9 },
    } };
  return { log, review: { context: structuredClone(githubContext), alerts: [alert] } };
}

test('Only an exact already-reviewed current GitHub false positive can pass', () => {
  const { log, review } = reviewedFixture();
  assert.deepEqual(summarizeSarif(log), counts(1));
  assert.deepEqual(summarizeSarif(log, review), counts(0, 1, 0, 1));
  log.runs[0].results[0].level = 'error';
  assert.deepEqual(summarizeSarif(log, review), counts(0, 1, 1, 1));
  delete log.runs[0].results[0].locations[0].physicalLocation.region.endLine;
  assert.deepEqual(summarizeSarif(log, review), counts(0, 1, 1, 1));
  delete log.runs[0].versionControlProvenance;
  assert.deepEqual(summarizeSarif(log, review), counts(0, 1, 1, 1));
  delete log.runs[0].automationDetails;
  assert.deepEqual(summarizeSarif(log, review), counts(1, 1, 1));
});

test('New, open, stale, differently reviewed and ambiguous findings remain blocking', () => {
  const mutations = [
    (r) => { r.alerts = []; }, (r) => { r.alerts[0].state = 'open'; },
    (r) => { r.alerts[0].most_recent_instance.state = 'open'; },
    (r) => { r.alerts[0].dismissed_reason = "won't fix"; },
    (r) => { r.alerts[0].most_recent_instance.ref = 'refs/heads/main'; },
    (r) => { r.alerts[0].most_recent_instance.commit_sha = 'b'.repeat(40); },
    (r) => { r.alerts[0].most_recent_instance.category = '/language:javascript-typescript'; },
    (r) => { r.alerts[0].most_recent_instance.analysis_key = 'other workflow'; },
    (r) => { r.alerts[0].rule.id = 'other'; },
    (r) => { r.alerts[0].most_recent_instance.location.path = 'src/other.go'; },
    ...['start_line', 'end_line', 'start_column', 'end_column'].map((key) => (r) => { r.alerts[0].most_recent_instance.location[key]++; }),
    (r) => { r.alerts.push(structuredClone(r.alerts[0])); },
    (r) => { const open = structuredClone(r.alerts[0]); open.state = 'open'; open.most_recent_instance.state = 'open'; r.alerts.push(open); },
  ];
  for (const mutate of mutations) {
    const { log, review } = reviewedFixture(); mutate(review);
    assert.deepEqual(summarizeSarif(log, review), counts(1));
  }
});

test('A dismissal cannot approve other SARIF source context or a hierarchical child rule', () => {
  for (const mutate of [
    (l) => { l.runs[0].automationDetails.id = '/language:javascript-typescript/'; },
    (l) => { l.runs[0].versionControlProvenance[0].revisionId = 'b'.repeat(40); },
    (l) => { l.runs[0].versionControlProvenance[0].branch = 'refs/heads/main'; },
    (l) => { l.runs[0].results[0].ruleId = 'high/child'; },
    (l) => { delete l.runs[0].results[0].locations[0].physicalLocation.region.startColumn; },
  ]) {
    const { log, review } = reviewedFixture(); mutate(log);
    assert.deepEqual(summarizeSarif(log, review), counts(1));
  }
});

test('GitHub metadata lookup fetches every page of both dismissed and open CodeQL alerts', () => {
  const { review } = reviewedFixture();
  const env = { GITHUB_REPOSITORY: githubContext.repository, GITHUB_REF: githubContext.ref,
    GITHUB_SHA: githubContext.sha, CODEQL_ANALYSIS_CATEGORY: githubContext.category, CODEQL_ANALYSIS_KEY: githubContext.analysisKey };
  const calls = [];
  const fetched = fetchGitHubReview(env, (command, args) => {
    if (command === 'git') { assert.deepEqual(args, ['rev-parse', 'HEAD']); return githubContext.sha; }
    assert.equal(command, 'gh'); assert.ok(args.includes('--paginate') && args.includes('--slurp'));
    assert.ok(args.includes(`ref=${githubContext.ref}`) && args.includes('tool_name=CodeQL'));
    calls.push(args.find((arg) => arg.startsWith('state=')));
    return calls.length === 1 ? JSON.stringify([[], review.alerts]) : JSON.stringify([[]]);
  });
  assert.deepEqual(calls, ['state=dismissed', 'state=open']);
  assert.deepEqual({ context: fetched.context, alerts: fetched.alerts }, review);
  for (const response of ['not JSON', '{}', '[]', '[{}]', '[[{}]]']) {
    assert.throws(() => fetchGitHubReview(env, (command) => command === 'git' ? githubContext.sha : response));
  }
  assert.throws(() => fetchGitHubReview(env, (command) => { if (command === 'git') return githubContext.sha; throw new Error('API unavailable'); }));
  assert.throws(() => fetchGitHubReview(env, (command) => { assert.equal(command, 'git'); return 'b'.repeat(40); }));
  assert.throws(() => fetchGitHubReview({ ...env, GITHUB_SHA: '' }, () => { assert.fail('unexpected API read'); }));
});

function baselineFixture({ context = githubContext, baseSHA = 'b'.repeat(40), headSHA = 'c'.repeat(40),
  blobSHA = 'd'.repeat(40), path = 'src/proxy.go', ruleId = 'high',
  region = { startLine: 10, startColumn: 3, endLine: 10, endColumn: 9 } } = {}) {
  const { log, review } = reviewedFixture();
  log.runs[0].versionControlProvenance = [{ repositoryUri: `https://github.com/${context.repository}`, revisionId: context.sha }];
  log.runs[0].tool.driver.rules[0].id = ruleId;
  log.runs[0].results[0].ruleId = ruleId;
  log.runs[0].results[0].locations[0].physicalLocation = { artifactLocation: { uri: path }, region };
  const alert = structuredClone(review.alerts[0]);
  alert.rule.id = ruleId;
  alert.most_recent_instance.ref = 'refs/heads/main';
  alert.most_recent_instance.commit_sha = baseSHA;
  alert.most_recent_instance.location = { path, start_line: region.startLine, end_line: region.endLine,
    start_column: region.startColumn, end_column: region.endColumn };
  const prNumber = Number(context.ref.split('/')[2]);
  const fixture = { log, current: [], baseline: [alert],
    pr: { number: prNumber, merge_commit_sha: context.sha, base: {
      ref: 'main', sha: baseSHA, repo: { full_name: context.repository },
    }, head: { sha: headSHA } },
    commit: `tree ${'e'.repeat(40)}\nparent ${baseSHA}\nparent ${headSHA}\n\nMerge PR\n`,
    tree: `100644 blob ${blobSHA}\t${path}\0`,
    contents: { type: 'file', path, sha: blobSHA }, calls: [],
  };
  const env = { GITHUB_REPOSITORY: context.repository, GITHUB_REF: context.ref,
    GITHUB_SHA: context.sha, CODEQL_ANALYSIS_CATEGORY: context.category, CODEQL_ANALYSIS_KEY: context.analysisKey };
  fixture.env = env;
  fixture.fetch = () => fetchGitHubReview(env, (command, args) => {
    fixture.calls.push([command, args]);
    if (fixture.fail?.(command, args)) throw new Error('TEST_SECRET: unavailable');
    if (command === 'git') {
      if (args[0] === 'rev-parse') return args[1] === '--show-toplevel' ? '/checkout' : context.sha;
      if (args[0] === 'cat-file') return fixture.commit;
      if (args[0] === 'ls-tree') return fixture.tree;
      if (args[0] === 'diff') return '';
      if (args[0] === 'check-ref-format') return '';
    }
    if (command === 'gh') {
      if (args.includes(`repos/${context.repository}/pulls/${prNumber}`)) return JSON.stringify(fixture.pr);
      if (args.includes(`repos/${context.repository}/contents/${path}`)) {
        assert.ok(args.includes(`ref=${baseSHA}`));
        return JSON.stringify(fixture.contents);
      }
      if (args.includes(`repos/${context.repository}/code-scanning/alerts`)) {
        const alerts = args.includes('ref=refs/heads/main') ? fixture.baseline : fixture.current;
        const state = args.includes('state=open') ? 'open' : 'dismissed';
        return JSON.stringify([[], alerts.filter((item) => item.state === state)]);
      }
    }
    assert.fail(`Unexpected command: ${command} ${args.join(' ')}`);
  });
  return fixture;
}

test('An exact reviewed PR-base finding passes only with an identical full source blob', () => {
  const f = baselineFixture();
  assert.deepEqual(summarizeSarif(f.log, f.fetch()), counts(0, 1, 0, 1));
  assert.ok(f.calls.some(([cmd, args]) => cmd === 'git' && args[0] === 'cat-file'));
  assert.ok(f.calls.some(([cmd, args]) => cmd === 'git' && args[0] === 'diff'));
  assert.ok(f.calls.some(([cmd, args]) => cmd === 'git' && args[0] === 'ls-tree'));
});

test('The live PR 109 finding matches alert 188 at the exact reviewed main revision', () => {
  // Sanitized GitHub evidence read on 2026-10-15. Artifact/rule shape is from the
  // actual main analysis 1940817995 SARIF; only analysis provenance is adapted to the PR.
  // No rule exemption is embedded in the gate.
  const f = baselineFixture({ context: { ...githubContext, repository: 'tunnexio/tunnex',
    ref: 'refs/pull/109/merge', sha: '149967a66ef1cebe42bf7a810db4e134908c57f0' },
    baseSHA: '38f07a0551dac6d0cb14560e64ed2525ac8d5817', headSHA: '0056dce8a01bea5cab0b1ba4a9744f59e15e64b9',
    blobSHA: 'c9b731f74826f40ee7d2a7984d1eac4795d1b1a9',
    path: 'apps/node/internal/serveraccess/rdp.go', ruleId: 'go/disabled-certificate-check',
    region: { startLine: 62, startColumn: 3, endLine: 62, endColumn: 27 },
  });
  f.baseline[0].number = 188;
  const run = f.log.runs[0], rule = run.tool.driver.rules[0];
  rule.properties['security-severity'] = '7.5';
  run.tool.extensions = [{ rules: [...Array.from({ length: 7 }, (_, i) => descriptor(`other-${i}`)), rule] }];
  run.tool.driver.rules = [];
  run.results[0].rule = { id: 'go/disabled-certificate-check', toolComponent: { index: 0 }, index: 7 };
  const artifact = run.results[0].locations[0].physicalLocation.artifactLocation;
  artifact.index = 5;
  run.artifacts = [...Array.from({ length: 5 }, () => ({})), { location: structuredClone(artifact) }];
  assert.deepEqual(summarizeSarif(f.log, f.fetch()), counts(0, 1, 0, 1));
  f.contents.sha = 'f'.repeat(40);
  assert.deepEqual(summarizeSarif(f.log, f.fetch()), counts(1));
});

test('An unchanged sink cannot inherit a baseline dismissal for cross-file flow or ambiguous current results', (t) => {
  for (const key of ['codeFlows', 'relatedLocations', 'stacks', 'graphs', 'graphTraversals', 'analysisTarget']) {
    const f = baselineFixture();
    f.log.runs[0].results[0][key] = key === 'codeFlows' ? [{ threadFlows: [{ locations: [{ location: {
      physicalLocation: { artifactLocation: { uri: 'src/new-untrusted-input.go' }, region: { startLine: 4 } },
    } }] }] }] : [];
    assert.deepEqual(summarizeSarif(f.log, f.fetch()), counts(1));
    assert.ok(!f.calls.some(([, args]) => args.includes('repos/owner/repository/pulls/10')));
  }
  const f = baselineFixture();
  const duplicate = structuredClone(f.log.runs[0].results[0]);
  duplicate.message = { text: 'A distinct source path to the same sink' };
  delete duplicate.locations[0].physicalLocation.region.endLine;
  f.log.runs[0].results.push(duplicate);
  assert.deepEqual(summarizeSarif(f.log, f.fetch()), counts(2));
  f.log.runs.push(structuredClone(f.log.runs[0]));
  for (const run of f.log.runs) run.results.length = 1;
  assert.deepEqual(summarizeSarif(f.log, f.fetch()), counts(2));
  const dir = mkdtempSync(join(tmpdir(), 'codeql-baseline-duplicates-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const files = f.log.runs.map((run, i) => {
    const file = join(dir, `${i}.sarif`); writeFileSync(file, JSON.stringify({ ...f.log, runs: [run] })); return file;
  });
  assert.throws(() => checkFiles(files, () => {}, f.fetch()), /2 blocking finding/);
  for (const mutate of [
    (r) => { r.provenance = { conversionSources: [{ uri: 'other.go' }] }; },
    (r) => { r.locations[0].logicalLocations = [{ fullyQualifiedName: 'other.function' }]; },
  ]) {
    const crossFile = baselineFixture(); mutate(crossFile.log.runs[0].results[0]);
    assert.deepEqual(summarizeSarif(crossFile.log, crossFile.fetch()), counts(1));
  }
});

test('Baseline source paths require a consistent artifact index and repository source root', () => {
  const fixture = () => {
    const f = baselineFixture(), run = f.log.runs[0];
    const artifact = run.results[0].locations[0].physicalLocation.artifactLocation;
    artifact.index = 0; artifact.uriBaseId = '%SRCROOT%';
    run.artifacts = [{ location: structuredClone(artifact) }];
    run.originalUriBaseIds = { '%SRCROOT%': { uri: 'file:///checkout/' } };
    return f;
  };
  const f = fixture(); assert.deepEqual(summarizeSarif(f.log, f.fetch()), counts(0, 1, 0, 1));
  for (const mutate of [
    (r) => { r.results[0].locations[0].physicalLocation.artifactLocation.index = 1; },
    (r) => { r.artifacts[0].location.uri = 'external/proxy.go'; },
    (r) => { r.artifacts[0].location.uriBaseId = '%OTHER%'; },
    (r) => { delete r.originalUriBaseIds; },
    (r) => { r.originalUriBaseIds['%SRCROOT%'].uri = 'file:///outside/'; },
    (r) => { r.originalUriBaseIds['%SRCROOT%'].uri = 'https://example.com/checkout/'; },
    (r) => { r.originalUriBaseIds['%SRCROOT%'].uriBaseId = '%OTHER%'; },
  ]) {
    const changed = fixture(); mutate(changed.log.runs[0]);
    assert.deepEqual(summarizeSarif(changed.log, changed.fetch()), counts(1));
  }
  f.fail = (command, args) => command === 'git' && args.includes('--show-toplevel');
  assert.throws(() => summarizeSarif(f.log, f.fetch()), /Cannot verify/);
});

test('Raw CodeQL 2.27.2 SRCROOT without a map requires an explicit verified workflow source root', () => {
  // Exact structural shape from PR109 Security attempt2's retained go.sarif: matching
  // artifact index, SRCROOT marker, no originalUriBaseIds/provenance, omitted endLine.
  const fixture = () => {
    const f = baselineFixture(), run = f.log.runs[0];
    delete run.versionControlProvenance;
    const physical = run.results[0].locations[0].physicalLocation;
    delete physical.region.endLine;
    physical.artifactLocation = { uri: 'src/proxy.go', uriBaseId: '%SRCROOT%', index: 0 };
    run.artifacts = [{ location: structuredClone(physical.artifactLocation) }];
    f.env.GITHUB_WORKSPACE = '/checkout';
    f.env.CODEQL_ANALYSIS_SOURCE_ROOT = '/checkout';
    return f;
  };
  const f = fixture();
  assert.deepEqual(summarizeSarif(f.log, f.fetch()), counts(0, 1, 0, 1));
  for (const mutate of [
    (x) => { delete x.env.CODEQL_ANALYSIS_SOURCE_ROOT; },
    (x) => { delete x.env.GITHUB_WORKSPACE; },
    (x) => { x.env.GITHUB_WORKSPACE = '/outside'; },
    (x) => { x.env.CODEQL_ANALYSIS_SOURCE_ROOT = '/outside'; },
    (x) => { x.log.runs[0].originalUriBaseIds = {}; },
    (x) => { x.log.runs[0].originalUriBaseIds = null; },
    (x) => { x.log.runs[0].originalUriBaseIds = { '%SRCROOT%': { uri: '%SRCROOT%' } }; },
    (x) => { x.log.runs[0].originalUriBaseIds = { '%SRCROOT%': { uri: 'file:///outside/' } }; },
    (x) => { x.log.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uriBaseId = 'UNKNOWN'; },
    (x) => { x.log.runs[0].artifacts[0].location.uriBaseId = 'UNKNOWN'; },
    (x) => { x.contents.sha = 'e'.repeat(40); },
  ]) {
    const changed = fixture(); mutate(changed);
    assert.deepEqual(summarizeSarif(changed.log, changed.fetch()), counts(1), mutate.toString());
  }
});

test('Baseline reconciliation blocks changed source, location, rule, context and review ambiguity', () => {
  const mutations = [
    (f) => { f.contents.sha = 'e'.repeat(40); },
    (f) => { f.baseline = []; },
    (f) => { f.baseline.push(structuredClone(f.baseline[0])); },
    (f) => { f.baseline[0].state = 'open'; f.baseline[0].most_recent_instance.state = 'open'; },
    (f) => { const open = structuredClone(f.baseline[0]); open.state = 'open'; open.most_recent_instance.state = 'open'; f.baseline.push(open); },
    (f) => { f.baseline[0].dismissed_reason = "won't fix"; },
    (f) => { f.baseline[0].most_recent_instance.state = 'open'; },
    (f) => { f.baseline[0].most_recent_instance.commit_sha = 'e'.repeat(40); },
    (f) => { f.baseline[0].most_recent_instance.ref = 'refs/heads/untrusted'; },
    (f) => { f.baseline[0].most_recent_instance.category = '/language:javascript-typescript'; },
    (f) => { f.baseline[0].most_recent_instance.analysis_key = 'different workflow'; },
    (f) => { f.baseline[0].rule.id = 'other'; },
    (f) => { f.baseline[0].most_recent_instance.location.path = 'src/other.go'; },
    ...['start_line', 'end_line', 'start_column', 'end_column'].map((key) => (f) => { f.baseline[0].most_recent_instance.location[key]++; }),
    (f) => { const open = reviewedFixture().review.alerts[0]; open.state = 'open'; open.most_recent_instance.state = 'open'; f.current.push(open); },
    (f) => { const open = reviewedFixture().review.alerts[0]; open.state = 'open'; open.most_recent_instance.state = 'open'; open.most_recent_instance.commit_sha = 'e'.repeat(40); f.current.push(open); },
    (f) => { f.log.runs[0].automationDetails.id = '/language:other/'; },
    (f) => { f.log.runs[0].versionControlProvenance[0].revisionId = 'e'.repeat(40); },
  ];
  for (const mutate of mutations) {
    const f = baselineFixture(); mutate(f);
    assert.deepEqual(summarizeSarif(f.log, f.fetch()), counts(1), mutate.toString());
  }
});

test('Missing or mismatched PR provenance and malformed source identity fail closed', () => {
  for (const mutate of [
    (f) => { f.pr = null; }, (f) => { f.pr.number = 11; },
    (f) => { f.pr.base.repo.full_name = 'other/repo'; },
    (f) => { f.pr.base.ref = ''; }, (f) => { f.pr.base.sha = 'not-a-sha'; },
    (f) => { f.pr.merge_commit_sha = 'e'.repeat(40); },
    (f) => { f.pr.head.sha = 'e'.repeat(40); },
    (f) => { f.commit = `parent ${'b'.repeat(40)}\n\nNot a merge\n`; },
    (f) => { f.tree = ''; }, (f) => { f.tree = f.tree.replace('100644 blob', '120000 blob'); },
    (f) => { f.tree += f.tree; },
    (f) => { f.contents.sha = 'not-a-sha'; },
    (f) => { f.contents.path = 'src/other.go'; }, (f) => { f.contents.type = 'symlink'; },
  ]) {
    const f = baselineFixture(); mutate(f);
    assert.throws(() => summarizeSarif(f.log, f.fetch()), undefined, mutate.toString());
  }
});

test('Every baseline API and Git verification failure blocks without leaking subprocess output', () => {
  const successful = baselineFixture(); summarizeSarif(successful.log, successful.fetch());
  for (const [command, args] of successful.calls) {
    const f = baselineFixture();
    f.fail = (cmd, argv) => cmd === command && JSON.stringify(argv) === JSON.stringify(args);
    assert.throws(() => summarizeSarif(f.log, f.fetch()), (error) => {
      assert.doesNotMatch(error.message, /TEST_SECRET/); return true;
    });
  }
});

test('The opt-in CLI applies reviewed metadata and keeps unknown, stale and API failure blocking', (t) => {
  const { log, review } = reviewedFixture();
  const dir = mkdtempSync(join(tmpdir(), 'codeql-reviewed-cli-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const gh = join(dir, 'gh');
  writeFileSync(gh, `#!/usr/bin/env node
if (process.env.TEST_GH_FAIL === '1') process.exit(1);
const alerts = ${JSON.stringify(review.alerts)};
const pr = ${JSON.stringify(baselineFixture().pr)};
console.log(JSON.stringify(process.argv.includes('repos/owner/repository/pulls/10') ? pr :
  process.argv.includes('state=dismissed') ? [[], alerts] : [[]]));
`);
  chmodSync(gh, 0o700);
  const git = join(dir, 'git');
  writeFileSync(git, `#!/usr/bin/env node
console.log(process.argv.includes('cat-file') ? ${JSON.stringify(baselineFixture().commit)} :
  process.env.TEST_CHECKOUT_SHA ?? process.env.GITHUB_SHA);
`);
  chmodSync(git, 0o700);
  const file = join(dir, 'go.sarif');
  const env = { ...process.env, PATH: `${dir}:${dirname(process.execPath)}:${process.env.PATH ?? ''}`,
    GITHUB_REPOSITORY: githubContext.repository, GITHUB_REF: githubContext.ref, GITHUB_SHA: githubContext.sha,
    CODEQL_ANALYSIS_CATEGORY: githubContext.category, CODEQL_ANALYSIS_KEY: githubContext.analysisKey };
  const run = (extra = {}) => spawnSync(process.execPath, [script, '--github-dismissals', file],
    { encoding: 'utf8', env: { ...env, ...extra } });
  writeFileSync(file, JSON.stringify(log));
  const accepted = run();
  assert.equal(accepted.status, 0, accepted.stdout + accepted.stderr);
  assert.match(accepted.stdout, /1 exact reviewed false positive/);
  assert.doesNotMatch(accepted.stdout, /blocking result:/);
  assert.equal(run({ GITHUB_SHA: 'b'.repeat(40) }).status, 1);
  assert.equal(run({ TEST_CHECKOUT_SHA: 'b'.repeat(40) }).status, 1);
  const failedAPI = run({ TEST_GH_FAIL: '1' });
  assert.equal(failedAPI.status, 1);
  assert.match(failedAPI.stderr, /Cannot read GitHub/);
  const unknown = structuredClone(log.runs[0].results[0]);
  unknown.locations[0].physicalLocation.region.startLine++;
  unknown.locations[0].physicalLocation.region.endLine++;
  log.runs[0].results.push(unknown);
  writeFileSync(file, JSON.stringify(log));
  const blocked = run();
  assert.equal(blocked.status, 1);
  assert.match(blocked.stdout, /blocking findings: 1/);
  assert.equal(blocked.stdout.split('\n').filter((line) => line.startsWith('blocking result: ')).length, 1);
});
