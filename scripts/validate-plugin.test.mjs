import assert from 'node:assert/strict';
import { test } from 'node:test';
import { judge } from './validate-plugin.mjs';

const TS5097 = "error TS5097: An import path can only end with a '.ts' extension when 'allowImportingTsExtensions' is enabled.";
const manifest = { file: 'plugin.json', type: 'plugin', errors: [], warnings: [] };
const hooks = warnings => ({ file: 'hooks/register.tsx', type: 'hooks', errors: [], warnings });

test('passes a clean report', () => {
  assert.equal(judge({ success: true, manifest, contents: [hooks([])] }).ok, true);
});

test('tolerates only TS5097 warnings from the hooks type check', () => {
  const verdict = judge({ success: false, manifest, contents: [hooks([{ path: 'line 1, column 1', message: TS5097 }])] });
  assert.equal(verdict.ok, true);
  assert.equal(verdict.tolerated.length, 1);
});

test('fails any other type error next to a tolerated one', () => {
  const verdict = judge({
    success: false,
    manifest,
    contents: [hooks([{ message: TS5097 }, { message: "error TS2741: Property 'isCollapsed' is missing" }])],
  });
  assert.equal(verdict.ok, false);
  assert.equal(verdict.blocking.length, 1);
});

test('fails TS5097 reported as an error or outside the hooks type check', () => {
  assert.equal(judge({ success: false, manifest, contents: [{ ...hooks([]), errors: [{ message: TS5097 }] }] }).ok, false);
  assert.equal(judge({ success: false, manifest: { ...manifest, warnings: [{ message: TS5097 }] }, contents: [] }).ok, false);
});

test('fails manifest warnings, which --strict treats as errors', () => {
  assert.equal(judge({ success: false, manifest: { ...manifest, warnings: [{ message: 'unknown field' }] }, contents: [] }).ok, false);
});

test('fails a failed report that carries no finding, and a report without a manifest', () => {
  assert.equal(judge({ success: false, manifest, contents: [] }).ok, false);
  assert.equal(judge({ success: true, contents: [] }).ok, false);
  assert.equal(judge(null).ok, false);
});
