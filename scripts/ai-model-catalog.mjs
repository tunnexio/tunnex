#!/usr/bin/env node
// Build-time data only. This does not import or execute upstream provider code.
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const directory = fileURLToPath(new URL('../apps/api/internal/aigateway/reference/', import.meta.url));
export const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const standardProviders = new Set(['openai', 'anthropic', 'gemini', 'openrouter', 'groq', 'mistral', 'cerebras', 'xai', 'deepseek']);
const providers = new Set([...standardProviders, 'azure', 'azure_ai']);
const modes = new Set(['chat', 'completion', 'embedding', 'audio_speech', 'audio_transcription', 'image_generation', 'video_generation', 'rerank']);
const modelID = /^[A-Za-z0-9][A-Za-z0-9_./:-]{0,254}$/;
const numeric = (value) => typeof value === 'number' && Number.isFinite(value) && value >= 0;
const ordered = (object) => Object.fromEntries(Object.entries(object).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
export const serialize = (value) => Buffer.from(JSON.stringify(value, null, 2) + '\n');

export function validatePin(pin) {
  if (pin.schema_version !== 1 || pin.repository !== 'https://github.com/BerriAI/litellm' || !/^[a-f0-9]{40}$/.test(pin.commit) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(pin.source_date) || pin.source_path !== 'model_prices_and_context_window.json' || pin.license_path !== 'LICENSE' || pin.license !== 'MIT' || ![pin.source_sha256, pin.license_sha256].every(v => /^[a-f0-9]{64}$/.test(v)) || !Number.isSafeInteger(pin.source_entries) || pin.source_entries <= 0 || !Number.isSafeInteger(pin.reference_entries) || pin.reference_entries <= 0) {
    throw new Error('Invalid model catalog source pin');
  }
  return pin;
}

// Preserve USD values in their original units. Missing fields are omitted; they
// must never be filled with zero. Retain tier/cache/media prices as metadata,
// without claiming that a two-token-rate estimate covers every billing unit.
export function priceUnit(key) {
  if (key.includes('dbu') || !key.includes('cost')) return undefined;
  if (key.includes('per_1k_tokens')) return 'USD/1000_tokens';
  if (key.includes('per_1k_calls')) return 'USD/1000_calls';
  if (key.includes('per_gb_per_day')) return 'USD/GB/day';
  if (key.includes('per_token') || key.includes('token_cost') || key.includes('per_audio_token') || key.includes('per_image_token') || key.includes('per_reasoning_token') || key.includes('per_video_token')) return 'USD/token';
  for (const unit of ['character', 'image', 'pixel', 'page', 'query', 'request', 'second', 'session', 'credit', 'unit']) {
    if (key.includes('per_' + unit)) return 'USD/' + unit;
  }
  return undefined;
}

function parseSource(sourceBytes) {
  const source = JSON.parse(sourceBytes.toString('utf8'));
  if (!source || Array.isArray(source) || typeof source !== 'object') throw new Error('Invalid catalog source');
  return source;
}

export function generateCatalog(sourceBytes, licenseBytes, pin) {
  validatePin(pin);
  if (sha256(sourceBytes) !== pin.source_sha256 || sha256(licenseBytes) !== pin.license_sha256) throw new Error('Pinned catalog source or license checksum mismatch');
  const source = parseSource(sourceBytes);
  if (Object.keys(source).length !== pin.source_entries) throw new Error('Catalog source completeness changed');
  const { entries, units } = deriveEntries(source);
  if (entries.length !== pin.reference_entries) throw new Error('Reference catalog completeness changed');
  for (const provider of standardProviders) {
    if (!entries.some(row => row.provider === provider && row.mode === 'chat')) throw new Error('Supported provider absent from reference');
  }
  return { schema_version: 1, provenance: pin, pricing_currency: 'USD', pricing_units: ordered(units), entries };
}

// Field-type validation and derivation, shared by the pinned build and refresh.
function deriveEntries(source) {
  const entries = [];
  const units = {};
  for (const sourceID of Object.keys(source).sort()) {
    const row = source[sourceID];
    if (!row || Array.isArray(row) || typeof row !== 'object') throw new Error('Invalid catalog source row');
    const provider = row.litellm_provider;
    if (!providers.has(provider) || !modes.has(row.mode)) continue;
    let id;
    if (sourceID.startsWith(provider + '/')) id = sourceID;
    else if (!sourceID.includes('/')) id = provider + '/' + sourceID;
    else continue; // A regional/image-size pricing path is not a model ID.
    if (!modelID.test(id)) throw new Error('Invalid reference model identifier');
    const metadata = {};
    const prices = {};
    for (const [key, value] of Object.entries(row)) {
      const unit = priceUnit(key);
      if (unit && value !== null) {
        if (typeof value === 'object' && !Array.isArray(value)) {
          if (!Object.values(value).every(numeric)) throw new Error('Invalid tier pricing value');
          prices[key] = ordered(value);
        } else {
          if (!numeric(value)) throw new Error('Invalid pricing value');
          prices[key] = value;
        }
        units[key] = unit;
      } else if (key.startsWith('supports_')) {
        if (typeof value !== 'boolean') throw new Error('Invalid model capability');
        metadata[key] = value;
      } else if (['max_tokens', 'max_input_tokens', 'max_output_tokens'].includes(key) && value !== null) {
        if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid model context limit');
        metadata[key] = value;
      } else if (['supported_endpoints', 'supported_modalities', 'supported_output_modalities'].includes(key)) {
        if (!Array.isArray(value) || !value.every(v => typeof v === 'string')) throw new Error('Invalid model metadata list');
        metadata[key] = value;
      } else if (['deprecation_date', 'source'].includes(key)) {
        if (typeof value !== 'string') throw new Error('Invalid model source metadata');
        metadata[key] = value;
      }
    }
    entries.push({ id, source_id: sourceID, provider, mode: row.mode, metadata: ordered(metadata), prices: ordered(prices) });
  }
  return { entries, units };
}

// AI-READY-1: a deliberate refresh to a newer immutable upstream commit. The
// new pin's hashes and counts come from the downloaded bytes; every guard of
// the pinned build still runs on the result. One extra guard: the reference
// set may not shrink by more than 10% (an upstream file that lost providers or
// rows must not silently become the new pin).
export const maxReferenceShrink = 0.1;
export function refreshPin(previous, sourceBytes, licenseBytes, commit, sourceDate) {
  validatePin(previous);
  const source = parseSource(sourceBytes);
  const { entries } = deriveEntries(source);
  const pin = validatePin({ ...previous, commit, source_date: sourceDate, source_sha256: sha256(sourceBytes), license_sha256: sha256(licenseBytes), source_entries: Object.keys(source).length, reference_entries: entries.length });
  if (entries.length < previous.reference_entries * (1 - maxReferenceShrink)) throw new Error(`Reference catalog shrank from ${previous.reference_entries} to ${entries.length} rows; review upstream before pinning`);
  generateCatalog(sourceBytes, licenseBytes, pin);
  return pin;
}

// What a refresh changes, for the reviewer: added and removed reference IDs
// and IDs whose token prices changed.
export function refreshSummary(before, after) {
  const index = (catalog) => new Map(catalog.entries.map(row => [row.id + ' ' + row.mode, row]));
  const a = index(before), b = index(after);
  const added = [...b.keys()].filter(k => !a.has(k)).sort();
  const removed = [...a.keys()].filter(k => !b.has(k)).sort();
  const repriced = [...b.keys()].filter(k => a.has(k) && ['input_cost_per_token', 'output_cost_per_token'].some(f => a.get(k).prices[f] !== b.get(k).prices[f])).sort();
  return { added, removed, repriced };
}

// The README names the pinned commit, its date and the row count.
export function updateReadme(text, previous, pin) {
  const replaced = text.split(previous.commit).join(pin.commit)
    .replace(/Source date: `[^`]+`\./, `Source date: \`${pin.source_date}\`.`)
    .replace(/embeds \d+ source rows/, `embeds ${pin.reference_entries} source rows`);
  if (!replaced.includes(pin.commit) || !replaced.includes(pin.source_date)) throw new Error('README pin lines not found');
  return replaced;
}

async function resolveCommit(ref) {
  if (ref !== 'main' && !/^[a-f0-9]{40}$/.test(ref)) throw new Error('Refresh needs a 40-character commit or main');
  const response = await fetch(`https://api.github.com/repos/BerriAI/litellm/commits/${ref}`, { redirect: 'error', headers: { Accept: 'application/vnd.github+json' }, signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error(`Cannot resolve upstream commit (${response.status})`);
  const body = await response.json();
  const commit = body?.sha, date = body?.commit?.committer?.date;
  if (!/^[a-f0-9]{40}$/.test(commit) || (ref !== 'main' && commit !== ref) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(date)) throw new Error('Unexpected upstream commit response');
  return { commit, date };
}

// Bifrost v2's datasheet contract uses provider (not the upstream SDK's field)
// and provider-qualified map keys. Its native loader strips the first prefix.
// Model parameters remain separate from prices and do not establish access.
export function generateNativeDatasheets(catalog) {
  const grouped = new Map();
  for (const row of catalog.entries) {
    const rows = grouped.get(row.id) ?? [];
    rows.push(row);
    grouped.set(row.id, rows);
  }
  const pricing = {}, parameters = {};
  for (const id of [...grouped.keys()].sort()) {
    const rows = grouped.get(id);
    const row = rows.find(row => row.source_id === id) ?? rows[0];
    parameters[id] = { provider: row.provider, base_model: id.slice(row.provider.length + 1), mode: row.mode, ...row.metadata };
    if (rows.some(other => other.mode !== row.mode || JSON.stringify(other.prices) !== JSON.stringify(row.prices))) continue;
    const prices = row.prices;
    if (!Object.keys(prices).length) continue;
    // Native token estimators substitute zero for an absent side. Leave the
    // entire native pricing record absent when token pricing is incomplete.
    if (['chat', 'completion'].includes(row.mode) && (!numeric(prices.input_cost_per_token) || !numeric(prices.output_cost_per_token))) continue;
    if (row.mode === 'embedding' && !numeric(prices.input_cost_per_token)) continue;
    pricing[id] = { provider: row.provider, base_model: id.slice(row.provider.length + 1), mode: row.mode, ...row.metadata, ...prices };
  }
  return { pricing, parameters };
}

async function download(path, pin) {
  const url = `https://raw.githubusercontent.com/BerriAI/litellm/${pin.commit}/${path}`;
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(60000) });
  if (!response.ok) throw new Error(`Cannot download pinned catalog source (${response.status})`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > 10000000) throw new Error('Catalog source exceeds build limit');
  return bytes;
}

export async function main(args) {
  const allowed = new Set(['--check', '--fetch', '--source', '--license', '--refresh']);
  let sourcePath, licensePath, refresh;
  for (let i = 0; i < args.length; i++) {
    if (!allowed.has(args[i])) throw new Error('Usage: ai-model-catalog.mjs [--check] [--fetch | --source FILE --license FILE] | --refresh COMMIT|main');
    if (args[i] === '--source') sourcePath = args[++i];
    else if (args[i] === '--license') licensePath = args[++i];
    else if (args[i] === '--refresh') refresh = args[++i];
  }
  if (refresh !== undefined && args.length !== 2) throw new Error('--refresh takes only its commit');
  if (Boolean(sourcePath) !== Boolean(licensePath) || (args.includes('--fetch') && sourcePath)) throw new Error('Choose one pinned source input');
  let pin = validatePin(JSON.parse(await readFile(resolve(directory, 'source.pin.json'), 'utf8')));
  if (refresh !== undefined) {
    const previous = pin;
    const before = JSON.parse(await readFile(resolve(directory, 'model-catalog.json'), 'utf8'));
    const { commit, date } = await resolveCommit(refresh);
    const target = { ...previous, commit };
    const sourceBytes = await download(previous.source_path, target), licenseBytes = await download(previous.license_path, target);
    pin = refreshPin(previous, sourceBytes, licenseBytes, commit, date);
    const summary = refreshSummary(before, generateCatalog(sourceBytes, licenseBytes, pin));
    await writeFile(resolve(directory, 'source.pin.json'), serialize(pin));
    const readme = resolve(directory, 'README.md');
    await writeFile(readme, updateReadme(await readFile(readme, 'utf8'), previous, pin));
    process.stdout.write(`Refresh ${previous.commit.slice(0, 12)} -> ${commit.slice(0, 12)} (${date})\n`);
    process.stdout.write(`Source rows ${previous.source_entries} -> ${pin.source_entries}; reference rows ${previous.reference_entries} -> ${pin.reference_entries}\n`);
    for (const [label, ids] of Object.entries(summary)) process.stdout.write(`${label} (${ids.length}): ${ids.slice(0, 40).join(', ')}${ids.length > 40 ? ', ...' : ''}\n`);
    await writeArtifacts(sourceBytes, licenseBytes, pin, false);
    await writeArtifacts(sourceBytes, licenseBytes, pin, true);
    return;
  }
  const sourceBytes = sourcePath ? await readFile(sourcePath) : await download(pin.source_path, pin);
  const licenseBytes = licensePath ? await readFile(licensePath) : await download(pin.license_path, pin);
  await writeArtifacts(sourceBytes, licenseBytes, pin, args.includes('--check'));
}

async function writeArtifacts(sourceBytes, licenseBytes, pin, check) {
  const catalog = generateCatalog(sourceBytes, licenseBytes, pin);
  const native = generateNativeDatasheets(catalog);
  const artifacts = {
    'model-catalog.json': serialize(catalog),
    'bifrost-pricing.json': serialize(native.pricing),
    'bifrost-model-parameters.json': serialize(native.parameters),
    'LiteLLM-LICENSE': licenseBytes,
  };
  artifacts['catalog-manifest.json'] = serialize({
    schema_version: 1,
    provenance: pin,
    reference_entries: catalog.entries.length,
    native_pricing_entries: Object.keys(native.pricing).length,
    native_parameter_entries: Object.keys(native.parameters).length,
    artifacts: Object.fromEntries(Object.entries(artifacts).map(([name, bytes]) => [name, sha256(bytes)])),
  });
  for (const [name, bytes] of Object.entries(artifacts)) {
    const path = resolve(directory, name);
    if (check) {
      if (!(await readFile(path)).equals(bytes)) throw new Error(`Generated catalog artifact drift: ${name}`);
    } else await writeFile(path, bytes);
  }
  process.stdout.write(`Pinned AI model catalog ${pin.commit}: ${pin.reference_entries} reference rows verified\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => { process.stderr.write(error.message + '\n'); process.exitCode = 1; });
}
