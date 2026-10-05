#!/usr/bin/env node
/*
 * Cross-language parity helper.
 *
 * Loads the frontend's real TypeScript adapter with a tiny TypeScript require
 * hook. This is test/handoff tooling only; it never imports or modifies the
 * production backend. The only Node-side dependency is `typescript`, which is
 * already a normal frontend development dependency.
 */
const fs = require('fs');
const path = require('path');
const Module = require('module');

if (process.argv.length !== 3) {
  console.error('usage: node compile_frontend_metadata.cjs <profile.json>');
  process.exit(2);
}

let ts;
try {
  ts = require('typescript');
} catch (error) {
  console.error('TypeScript is required to run frontend/backend parity tests. Run from an eleVADR checkout with frontend dependencies installed.');
  process.exit(3);
}

require.extensions['.ts'] = function compileTypeScript(mod, filename) {
  const source = fs.readFileSync(filename, 'utf8');
  const output = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      moduleResolution: ts.ModuleResolutionKind.NodeJs,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
      skipLibCheck: true,
    },
    fileName: filename,
    reportDiagnostics: false,
  });
  mod._compile(output.outputText, filename);
};

const profilePath = path.resolve(process.argv[2]);
const repoRoot = path.resolve(__dirname, '..', '..');
const adapterPath = path.join(
  repoRoot,
  'frontend',
  'src',
  'app',
  'components',
  'DetectionConfiguration',
  'analysisContextAdapter.ts',
);
const { compileDetectionContextMetadata } = require(adapterPath);
const profile = JSON.parse(fs.readFileSync(profilePath, 'utf8'));
const metadata = compileDetectionContextMetadata(profile);
process.stdout.write(`${JSON.stringify(metadata, null, 2)}\n`);
