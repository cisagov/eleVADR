const fs = require('fs');
const path = require('path');
function loadTypeScript() {
  const candidates = [
    'typescript',
    path.join(__dirname, '..', '..', 'frontend', 'node_modules', 'typescript'),
  ];
  for (const candidate of candidates) {
    try {
      return require(candidate);
    } catch (error) {
      // Try the next resolver location.
    }
  }
  console.error(
    'TypeScript is required. Install frontend dependencies (pnpm install) or set NODE_PATH to frontend\\node_modules.',
  );
  process.exit(3);
}

const ts = loadTypeScript();

const root = path.resolve(__dirname, '..', '..', 'frontend', 'src');
const files = [];
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (/\.(ts|tsx)$/.test(entry.name) && !entry.name.endsWith('.d.ts')) files.push(full);
  }
}
walk(root);
let errors = 0;
for (const file of files) {
  const source = fs.readFileSync(file, 'utf8');
  const result = ts.transpileModule(source, {
    fileName: file,
    reportDiagnostics: true,
    compilerOptions: {
      target: ts.ScriptTarget.ES2020,
      module: ts.ModuleKind.ESNext,
      jsx: ts.JsxEmit.ReactJSX,
      esModuleInterop: true,
      allowSyntheticDefaultImports: true,
      moduleResolution: ts.ModuleResolutionKind.Bundler ?? ts.ModuleResolutionKind.NodeJs,
    },
  });
  for (const diagnostic of result.diagnostics || []) {
    if (diagnostic.category !== ts.DiagnosticCategory.Error) continue;
    errors += 1;
    const msg = ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n');
    const pos = diagnostic.start != null
      ? ts.getLineAndCharacterOfPosition(ts.createSourceFile(file, source, ts.ScriptTarget.ES2020, true), diagnostic.start)
      : null;
    console.error(`${path.relative(root, file)}${pos ? `:${pos.line + 1}:${pos.character + 1}` : ''}: ${msg}`);
  }
}
console.log(`Frontend transpilation: checked ${files.length} TS/TSX files; ${errors} error(s).`);
process.exit(errors ? 1 : 0);
