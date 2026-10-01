import assert from 'node:assert/strict';
import test from 'node:test';
import { generateCatalog, generateNativeDatasheets, serialize, sha256, priceUnit } from './ai-model-catalog.mjs';

function fixture(extra = {}) {
  const source = Object.fromEntries(['openai', 'anthropic', 'gemini', 'openrouter', 'groq', 'mistral', 'cerebras', 'xai', 'deepseek'].map(provider => [provider + '/test', { litellm_provider: provider, mode: 'chat', max_input_tokens: 1024, supports_vision: false, input_cost_per_token: 0.000001, output_cost_per_token: 0.000002 }]));
  Object.assign(source, extra);
  const sourceBytes = serialize(source), licenseBytes = Buffer.from('MIT fixture\n');
  const pin = { schema_version: 1, repository: 'https://github.com/BerriAI/litellm', commit: 'a'.repeat(40), source_date: '2026-09-06T01:12:56Z', source_path: 'model_prices_and_context_window.json', source_sha256: sha256(sourceBytes), license_path: 'LICENSE', license: 'MIT', license_sha256: sha256(licenseBytes), source_entries: Object.keys(source).length, reference_entries: Object.keys(source).length };
  return { sourceBytes, licenseBytes, pin };
}
const generate = ({ sourceBytes, licenseBytes, pin }) => generateCatalog(sourceBytes, licenseBytes, pin);

test('snapshot derivation is byte reproducible and carries audited provenance', () => {
  const f = fixture();
  const first = generate(f), second = generate(f);
  assert.deepEqual(serialize(first), serialize(second));
  assert.deepEqual(first.provenance, f.pin);
  assert.equal(first.pricing_currency, 'USD');
  assert.equal(first.entries[0].provider, 'anthropic');
  assert.equal(first.entries[0].metadata.supports_vision, false);
});

test('source/license drift and incomplete source fail the build', () => {
  const f = fixture();
  assert.throws(() => generate({ ...f, sourceBytes: Buffer.concat([f.sourceBytes, Buffer.from(' ')]) }), /checksum/);
  assert.throws(() => generate({ ...f, licenseBytes: Buffer.from('changed') }), /checksum/);
  assert.throws(() => generate({ ...f, pin: { ...f.pin, source_entries: 100 } }), /completeness/);
  assert.throws(() => generate({ ...f, pin: { ...f.pin, reference_entries: 100 } }), /completeness/);
  assert.throws(() => generate({ ...f, pin: { ...f.pin, commit: 'main' } }), /pin/);
});

test('missing prices remain omitted, real zero prices remain zero, mixed units remain distinct', () => {
  const f = fixture({
    'openai/unknown': { litellm_provider: 'openai', mode: 'chat', input_cost_per_token: 0.1, output_cost_per_token: null },
    'openai/free': { litellm_provider: 'openai', mode: 'chat', input_cost_per_token: 0, output_cost_per_token: 0 },
    'openai/image': { litellm_provider: 'openai', mode: 'image_generation', output_cost_per_image: 0.04 },
    'openai/audio': { litellm_provider: 'openai', mode: 'audio_transcription', input_cost_per_second: 0.0001 },
  });
  const catalog = generate(f), native = generateNativeDatasheets(catalog);
  assert.equal(catalog.entries.find(row => row.id === 'openai/unknown').prices.output_cost_per_token, undefined);
  assert.equal(native.pricing['openai/unknown'], undefined);
  assert.equal(native.parameters['openai/unknown'].mode, 'chat');
  assert.equal(native.pricing['openai/free'].output_cost_per_token, 0);
  assert.equal(catalog.pricing_units.output_cost_per_image, 'USD/image');
  assert.equal(catalog.pricing_units.input_cost_per_second, 'USD/second');
  assert.equal(native.pricing['openai/image'].output_cost_per_token, undefined);
  assert.equal(priceUnit('input_dbu_cost_per_token'), undefined);
  assert.equal(priceUnit('computer_use_input_cost_per_1k_tokens'), 'USD/1000_tokens');
});

test('conflicting alias prices are unknown instead of map-order-dependent', () => {
  const f = fixture({ test: { litellm_provider: 'openai', mode: 'chat', input_cost_per_token: 0, output_cost_per_token: 0 } });
  const native = generateNativeDatasheets(generate(f));
  assert.equal(native.pricing['openai/test'], undefined);
  assert.equal(native.parameters['openai/test'].provider, 'openai');
});

test('invalid costs, capability flags and context limits fail the build', () => {
  for (const extra of [{ input_cost_per_token: -1 }, { supports_vision: 'yes' }, { max_input_tokens: 1.5 }, { output_cost_per_image: '0.01' }]) {
    const f = fixture({ 'openai/test': { litellm_provider: 'openai', mode: 'chat', input_cost_per_token: 1, output_cost_per_token: 1, ...extra } });
    assert.throws(() => generate(f), /Invalid/);
  }
});

test('regional and image-size paths are excluded from model suggestions', () => {
  const f = fixture({ '512x512/openai/image': { litellm_provider: 'openai', mode: 'image_generation', output_cost_per_image: 0.02 } });
  f.pin.reference_entries--;
  const catalog = generate(f);
  assert.equal(catalog.entries.some(row => row.id.includes('512x512')), false);
});
