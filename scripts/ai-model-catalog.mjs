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

export function generateCatalog(sourceBytes, licenseBytes, pin) {
  validatePin(pin);
  if (sha256(sourceBytes) !== pin.source_sha256 || sha256(licenseBytes) !== pin.license_sha256) throw new Error('Pinned catalog source or license checksum mismatch');
  const source = JSON.parse(sourceBytes.toString('utf8'));
  if (!source || Array.isArray(source) || typeof source !== 'object' || Object.keys(source).length !== pin.source_entries) throw new Error('Catalog source completeness changed');
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
  if (entries.length !== pin.reference_entries) throw new Error('Reference catalog completeness changed');
  for (const provider of standardProviders) {
    if (!entries.some(row => row.provider === provider && row.mode === 'chat')) throw new Error('Supported provider absent from reference');
  }
  return { schema_version: 1, provenance: pin, pricing_currency: 'USD', pricing_units: ordered(units), entries };
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
  const allowed = new Set(['--check', '--fetch', '--source', '--license']);
  let sourcePath, licensePath;
  for (let i = 0; i < args.length; i++) {
    if (!allowed.has(args[i])) throw new Error('Usage: ai-model-catalog.mjs [--check] [--fetch | --source FILE --license FILE]');
    if (args[i] === '--source') sourcePath = args[++i];
    else if (args[i] === '--license') licensePath = args[++i];
  }
  if (Boolean(sourcePath) !== Boolean(licensePath) || (args.includes('--fetch') && sourcePath)) throw new Error('Choose one pinned source input');
  const pin = validatePin(JSON.parse(await readFile(resolve(directory, 'source.pin.json'), 'utf8')));
  const sourceBytes = sourcePath ? await readFile(sourcePath) : await download(pin.source_path, pin);
  const licenseBytes = licensePath ? await readFile(licensePath) : await download(pin.license_path, pin);
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
    if (args.includes('--check')) {
      if (!(await readFile(path)).equals(bytes)) throw new Error(`Generated catalog artifact drift: ${name}`);
    } else await writeFile(path, bytes);
  }
  process.stdout.write(`Pinned AI model catalog ${pin.commit}: ${pin.reference_entries} reference rows verified\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => { process.stderr.write(error.message + '\n'); process.exitCode = 1; });
}
