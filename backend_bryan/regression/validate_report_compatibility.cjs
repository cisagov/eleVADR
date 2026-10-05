const fs = require("fs");
const path = require("path");
const Module = require("module");

function loadTypeScript() {
  try { return require("typescript"); } catch (_) {
    return require(path.resolve(__dirname, "../../frontend/node_modules/typescript"));
  }
}

const ts = loadTypeScript();
const root = path.resolve(__dirname, "../..");
const sourcePath = path.join(root, "frontend/src/app/utils/reportCompatibility.ts");
const source = fs.readFileSync(sourcePath, "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  fileName: sourcePath,
});
const mod = new Module(sourcePath, module);
mod.filename = sourcePath;
mod.paths = Module._nodeModulePaths(path.dirname(sourcePath));
mod._compile(compiled.outputText, sourcePath);
const { normalizeElevadrReport } = mod.exports;

const fixtures = path.join(__dirname, "report_compatibility_fixtures");
const load = (name) => JSON.parse(fs.readFileSync(path.join(fixtures, name), "utf8"));
const assert = (condition, message) => { if (!condition) throw new Error(message); };

const v1 = normalizeElevadrReport(load("legacy_v1_minimal.json"));
assert(v1.report.report_version === "2.0.0", "v1 fixture was not normalized to v2");
assert(v1.migrated === true, "v1 fixture should be marked migrated");
assert(v1.report.modules.service_panel.num_known_services === 3, "v1 service counts were not preserved");
assert(Array.isArray(v1.report.modules.ot_devices), "missing module defaults were not materialized");

const camel = normalizeElevadrReport(load("legacy_unversioned_camelcase.json"));
assert(camel.sourceVersion === "legacy-unversioned", "unversioned source family not identified");
assert(camel.report.report_id === "legacy-unversioned-camel", "camelCase reportId alias not preserved");
assert(camel.report.modules.device_panel.ot_hosts === 1, "camelCase device panel was not normalized");
assert(camel.report.modules.ot_devices.length === 1, "camelCase OT devices were not preserved");

const sparse = normalizeElevadrReport(load("current_v2_sparse.json"));
assert(sparse.migrated === false, "current v2 fixture should not be marked migrated");
assert(Array.isArray(sparse.report.modules.connection_success_panel.connections), "sparse v2 defaults missing");

let rejected = false;
try { normalizeElevadrReport(load("unsupported_v3.json")); } catch (error) {
  rejected = /Unsupported eleVADR report version/.test(String(error && error.message));
}
assert(rejected, "future major version must be rejected rather than guessed");
console.log("Report compatibility: 4 fixtures passed (v1, unversioned legacy, sparse v2, unsupported future version).")
