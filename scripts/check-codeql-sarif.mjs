import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { pathToFileURL } from 'node:url';

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const has = (value, key) => Object.hasOwn(value, key);
const refuse = (message) => { throw new Error(message); };
const text = (value) => typeof value === 'string' && value.length > 0;
const index = (value) => Number.isSafeInteger(value) && value >= 0;

// SARIF 2.1.0 §§3.27.5–7, 3.52, 3.54: toolComponent.index addresses extensions,
// while an absent component reference addresses the driver. Supplied selectors must agree.
function ruleForResult(tool, result) {
  const reference = has(result, 'rule') ? result.rule : {};
  if (!object(reference)) refuse('Invalid rule reference');
  for (const [alias, field] of [['ruleId', 'id'], ['ruleIndex', 'index']]) {
    if (has(result, alias) && has(reference, field) && result[alias] !== reference[field]) {
      refuse('Conflicting result rule selectors');
    }
  }
  const id = reference.id ?? result.ruleId;
  const ruleIndex = reference.index ?? result.ruleIndex;
  if (id !== undefined && !text(id) || ruleIndex !== undefined && !index(ruleIndex)) {
    refuse('Invalid result rule selector');
  }
  if (has(reference, 'id') && !text(reference.id) ||
      has(reference, 'index') && !index(reference.index) ||
      has(reference, 'guid') && !text(reference.guid)) refuse('Invalid rule reference selector');
  const extensions = has(tool, 'extensions') ? tool.extensions : [];
  if (!Array.isArray(extensions) || extensions.some((component) => !object(component))) {
    refuse('Invalid tool extensions');
  }
  let component = tool.driver;
  if (has(reference, 'toolComponent')) {
    const selector = reference.toolComponent;
    if (!object(selector)) refuse('Invalid tool component reference');
    if (has(selector, 'index')) {
      if (!index(selector.index) || selector.index >= extensions.length) refuse('Unknown tool extension');
      component = extensions[selector.index];
    } else if (has(selector, 'guid')) {
      const matches = [tool.driver, ...extensions].filter((candidate) => candidate.guid === selector.guid);
      if (!text(selector.guid) || matches.length !== 1) refuse('Unknown or ambiguous tool component GUID');
      [component] = matches;
    }
    for (const key of ['name', 'guid']) {
      if (has(selector, key) && (!text(selector[key]) || selector[key] !== component[key])) {
        refuse('Conflicting tool component selectors');
      }
    }
  }
  const rules = has(component, 'rules') ? component.rules : [];
  if (!Array.isArray(rules) || rules.some((rule) => !object(rule) || !text(rule.id))) {
    refuse('Invalid rule metadata');
  }
  // SARIF permits one additional hierarchical component in a result's rule ID.
  const matchesId = (rule) => id === undefined || id === rule.id ||
    (id.startsWith(`${rule.id}/`) && !id.slice(rule.id.length + 1).includes('/') && id.length > rule.id.length + 1);
  let rule;
  if (ruleIndex !== undefined) {
    rule = rules[ruleIndex];
  } else {
    const matches = rules.filter((candidate) => has(reference, 'guid')
      ? candidate.guid === reference.guid : id !== undefined && matchesId(candidate));
    if (matches.length !== 1) refuse('Unknown or ambiguous result rule');
    [rule] = matches;
  }
  if (!rule || !matchesId(rule) || has(reference, 'guid') && rule.guid !== reference.guid) {
    refuse('Conflicting or unknown result rule metadata');
  }
  return rule;
}

function securityScore(rule) {
  const properties = has(rule, 'properties') ? rule.properties : {};
  if (!object(properties)) refuse('Invalid rule properties');
  if (has(properties, 'tags') && (!Array.isArray(properties.tags) || properties.tags.some((tag) => !text(tag)))) {
    refuse('Invalid rule tags');
  }
  if (!has(properties, 'security-severity')) {
    if (Array.isArray(properties.tags) && properties.tags.includes('security')) {
      refuse('Security rule is missing security-severity');
    }
    return undefined;
  }
  const raw = properties['security-severity'];
  if (typeof raw !== 'number' && (typeof raw !== 'string' || !/^\d+(?:\.\d+)?$/.test(raw))) {
    refuse('Invalid security-severity');
  }
  const score = Number(raw);
  if (!Number.isFinite(score) || score < 0 || score > 10) refuse('Invalid security-severity');
  return score;
}

// Query both states so an open finding at the same location cannot inherit another alert's dismissal.
export function fetchGitHubReview(env = process.env, execute = execFileSync) {
  const context = {
    repository: env.GITHUB_REPOSITORY, ref: env.GITHUB_REF, sha: env.GITHUB_SHA,
    category: env.CODEQL_ANALYSIS_CATEGORY, analysisKey: env.CODEQL_ANALYSIS_KEY,
  };
  if (!/^[\w.-]+\/[\w.-]+$/.test(context.repository ?? '') || !text(context.ref) ||
      !/^[a-f0-9]{40}$/.test(context.sha ?? '') || !text(context.category) || !text(context.analysisKey)) {
    refuse('Missing exact GitHub analysis context');
  }
  let checkoutSHA;
  try { checkoutSHA = execute('git', ['rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim(); }
  catch { refuse('Cannot verify analyzed checkout'); }
  if (checkoutSHA !== context.sha) refuse('Analyzed checkout does not match GITHUB_SHA');
  const alerts = [];
  for (const state of ['dismissed', 'open']) {
    let pages;
    try {
      pages = JSON.parse(execute('gh', ['api', '--method', 'GET', '--paginate', '--slurp',
        `repos/${context.repository}/code-scanning/alerts`, '-f', `ref=${context.ref}`,
        '-f', `state=${state}`, '-f', 'tool_name=CodeQL', '-f', 'per_page=100'],
      { encoding: 'utf8', timeout: 30000, maxBuffer: 32 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }));
    } catch { refuse('Cannot read GitHub CodeQL dismissal metadata'); }
    if (!Array.isArray(pages) || pages.length === 0 || pages.some((page) => !Array.isArray(page))) {
      refuse('Malformed GitHub CodeQL dismissal metadata');
    }
    for (const alert of pages.flat()) {
      if (!object(alert) || !Number.isSafeInteger(alert.number) || !object(alert.rule) || !text(alert.rule.id) ||
          !object(alert.tool) || alert.tool.name !== 'CodeQL' || !['open', 'dismissed', 'fixed'].includes(alert.state) ||
          !object(alert.most_recent_instance) || !object(alert.most_recent_instance.location)) {
        refuse('Malformed GitHub CodeQL alert');
      }
      alerts.push(alert);
    }
  }
  return { context, alerts };
}

function reviewedFalsePositive(run, result, review) {
  if (!review) return false;
  const { context, alerts } = review;
  if (run.tool.driver.name !== 'CodeQL' || result.locations?.length !== 1) return false;
  // Raw CodeQL SARIF may omit exporter-added provenance. The fetch binds checkout SHA;
  // source metadata, when present, must independently agree with that exact analysis.
  if (![context.category, `${context.category}/`].includes(run.automationDetails?.id)) return false;
  if (has(run, 'versionControlProvenance') && (!Array.isArray(run.versionControlProvenance) ||
      !run.versionControlProvenance.some((source) => source.revisionId === context.sha &&
        source.repositoryUri === `https://github.com/${context.repository}` &&
        (!has(source, 'branch') || source.branch === context.ref)))) return false;
  const physical = result.locations[0].physicalLocation;
  if (!object(physical) || !object(physical.region) || !text(physical.artifactLocation?.uri)) return false;
  let path;
  try { path = decodeURIComponent(physical.artifactLocation.uri); } catch { return false; }
  if (path.startsWith('/') || path.includes('\\') || path.split('/').some((part) => !part || part === '.' || part === '..')) return false;
  const region = physical.region;
  const point = {
    path, start_line: region.startLine, end_line: region.endLine ?? region.startLine,
    start_column: region.startColumn, end_column: region.endColumn,
  };
  if (Object.entries(point).some(([key, value]) => key !== 'path' && (!Number.isSafeInteger(value) || value < 1))) return false;
  const ruleId = result.rule?.id ?? result.ruleId;
  const matches = alerts.filter((alert) => {
    const instance = alert.most_recent_instance;
    return alert.rule.id === ruleId && instance.ref === context.ref && instance.commit_sha === context.sha &&
      instance.category === context.category && instance.analysis_key === context.analysisKey &&
      Object.entries(point).every(([key, value]) => instance.location[key] === value);
  });
  return matches.length === 1 && matches[0].state === 'dismissed' &&
    matches[0].dismissed_reason === 'false positive' && matches[0].most_recent_instance.state === 'dismissed';
}

// GitHub uses rule.properties.security-severity for High/Critical, independently
// of result.level. Keep the previous gate's explicit error-level blocking as well.
// https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
export function summarizeSarif(log, review) {
  if (!object(log) || log.version !== '2.1.0' || !Array.isArray(log.runs) || log.runs.length === 0) {
    refuse('Missing or invalid SARIF runs');
  }
  const counts = { highCritical: 0, errorLevel: 0, reviewedFalsePositives: 0, blocking: 0 };
  for (const run of log.runs) {
    if (!object(run) || !object(run.tool) || !object(run.tool.driver) || !text(run.tool.driver.name)) refuse('Missing SARIF tool driver');
    const results = has(run, 'results') ? run.results : [];
    if (!Array.isArray(results)) refuse('Invalid SARIF results');
    for (const result of results) {
      if (!object(result)) refuse('Invalid SARIF result');
      if (has(result, 'level') && !['none', 'note', 'warning', 'error'].includes(result.level)) {
        refuse('Invalid SARIF result level');
      }
      const highCritical = securityScore(ruleForResult(run.tool, result)) >= 7;
      const errorLevel = result.level === 'error';
      const reviewed = (highCritical || errorLevel) && reviewedFalsePositive(run, result, review);
      counts.highCritical += Number(highCritical);
      counts.errorLevel += Number(errorLevel);
      counts.reviewedFalsePositives += Number(reviewed);
      counts.blocking += Number((highCritical || errorLevel) && !reviewed);
    }
  }
  return counts;
}

export function checkFiles(files, output = console.log, review) {
  if (files.length === 0) refuse('CodeQL ran but produced NO SARIF — the scan did not analyse anything');
  let blocking = 0;
  for (const file of files) {
    let log;
    try { log = JSON.parse(readFileSync(file, 'utf8')); }
    catch { refuse(`Cannot read valid SARIF: ${basename(file)}`); }
    const counts = summarizeSarif(log, review);
    output(`  ${basename(file)}: ${counts.highCritical} high/critical security finding(s), ${counts.errorLevel} error-level result(s), ${counts.reviewedFalsePositives} exact reviewed false positive(s)`);
    blocking += counts.blocking;
  }
  output(`blocking findings: ${blocking}`);
  if (blocking !== 0) refuse(`CodeQL reported ${blocking} blocking finding(s) — see the Security tab`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const args = process.argv.slice(2);
    const review = args[0] === '--github-dismissals' ? fetchGitHubReview() : undefined;
    checkFiles(review ? args.slice(1) : args, console.log, review);
  }
  catch (error) {
    console.error(`::error::${error.message}`);
    process.exitCode = 1;
  }
}
