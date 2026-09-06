import { pathToFileURL } from 'node:url';

// A conditional skip is valid only when the successful classifier explicitly
// disabled that lane. Missing output, cancelled jobs and unknown states fail.
export function validateGates(needs) {
  const errors = [];
  const required = ['scope', 'contracts', 'codegen', 'api', 'tooling', 'web'];
  for (const name of required) {
    if (!needs?.[name]) errors.push(`missing lane: ${name}`);
  }
  const outputs = needs?.scope?.outputs ?? {};
  for (const name of ['go', 'web', 'codegen', 'docs_only']) {
    if (!['true', 'false'].includes(outputs[name])) errors.push(`invalid scope: ${name}`);
  }
  if (outputs.docs_only === 'true' &&
      ['go', 'web', 'codegen'].some(name => outputs[name] !== 'false')) {
    errors.push('inconsistent docs-only classification');
  }
  for (const name of required) {
    const flag = { api: 'go', tooling: 'go', codegen: 'codegen' }[name];
    const expected = flag && outputs[flag] === 'false' ? 'skipped' : 'success';
    if (needs?.[name]?.result !== expected) {
      errors.push(`${name}: expected ${expected}, got ${needs?.[name]?.result ?? 'missing'}`);
    }
  }
  return errors;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const errors = validateGates(JSON.parse(process.env.GATE_NEEDS));
    if (errors.length) throw new Error(errors.join('\n'));
    console.log('All applicable CI lanes passed on this run.');
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
