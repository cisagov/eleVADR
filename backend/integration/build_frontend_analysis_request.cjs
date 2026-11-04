#!/usr/bin/env node
/* Test/handoff helper: execute the real frontend request builder. */
const fs = require("fs");
const path = require("path");

if (process.argv.length !== 3) {
  console.error(
    "usage: node build_frontend_analysis_request.cjs <profile.json>",
  );
  process.exit(2);
}

function loadTypeScript() {
  const candidates = [
    "typescript",
    path.join(__dirname, "..", "..", "frontend", "node_modules", "typescript"),
  ];
  for (const candidate of candidates) {
    try {
      return require(candidate);
    } catch (error) {
      // Try the next resolver location.
    }
  }
  console.error(
    "TypeScript is required. Install frontend dependencies (pnpm install) or set NODE_PATH to frontend\\node_modules.",
  );
  process.exit(3);
}

const ts = loadTypeScript();

require.extensions[".ts"] = function compileTypeScript(mod, filename) {
  const source = fs.readFileSync(filename, "utf8");
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
const repoRoot = path.resolve(__dirname, "..", "..");
const contractPath = path.join(
  repoRoot,
  "frontend",
  "src",
  "app",
  "components",
  "DetectionConfiguration",
  "analysisRequest.ts",
);
const { buildDetectionAnalysisRequest } = require(contractPath);
const profile = JSON.parse(fs.readFileSync(profilePath, "utf8"));
process.stdout.write(
  `${JSON.stringify(buildDetectionAnalysisRequest(profile), null, 2)}\n`,
);
