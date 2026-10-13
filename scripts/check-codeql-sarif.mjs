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

// GitHub uses rule.properties.security-severity for High/Critical, independently
// of result.level. Keep the previous gate's explicit error-level blocking as well.
// https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
export function summarizeSarif(log) {
  if (!object(log) || log.version !== '2.1.0' || !Array.isArray(log.runs) || log.runs.length === 0) {
    refuse('Missing or invalid SARIF runs');
  }
  const counts = { highCritical: 0, errorLevel: 0, blocking: 0 };
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
      counts.highCritical += Number(highCritical);
      counts.errorLevel += Number(errorLevel);
      counts.blocking += Number(highCritical || errorLevel);
    }
  }
  return counts;
}

export function checkFiles(files, output = console.log) {
  if (files.length === 0) refuse('CodeQL ran but produced NO SARIF — the scan did not analyse anything');
  let blocking = 0;
  for (const file of files) {
    let log;
    try { log = JSON.parse(readFileSync(file, 'utf8')); }
    catch { refuse(`Cannot read valid SARIF: ${basename(file)}`); }
    const counts = summarizeSarif(log);
    output(`  ${basename(file)}: ${counts.highCritical} high/critical security finding(s), ${counts.errorLevel} error-level result(s)`);
    blocking += counts.blocking;
  }
  output(`blocking findings: ${blocking}`);
  if (blocking !== 0) refuse(`CodeQL reported ${blocking} blocking finding(s) — see the Security tab`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { checkFiles(process.argv.slice(2)); }
  catch (error) {
    console.error(`::error::${error.message}`);
    process.exitCode = 1;
  }
}
