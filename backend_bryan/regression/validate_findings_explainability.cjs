const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..", "..");
const drawerPath = path.join(root, "frontend", "src", "app", "components", "EntityDrawer", "EntityDrawer.tsx");
const findingsPath = path.join(root, "frontend", "src", "app", "components", "FindingsPanel", "FindingsPanel.tsx");
const testPath = path.join(root, "frontend", "src", "tests", "FindingsExplainability.test.tsx");

function read(file) {
  if (!fs.existsSync(file)) throw new Error(`Required explainability file is missing: ${path.relative(root, file)}`);
  return fs.readFileSync(file, "utf8");
}

function requireText(source, needle, label) {
  if (!source.includes(needle)) throw new Error(`Findings explainability contract missing ${label}: ${needle}`);
}

const drawer = read(drawerPath);
const findings = read(findingsPath);
const tests = read(testPath);

[
  ["Why was this flagged?", "decision-explanation heading"],
  ["What was observed", "decision-explanation observation step"],
  ["What rule evaluated it", "decision-explanation detector step"],
  ["What context affected the decision", "decision-explanation context step"],
  ["Why the result became a finding", "decision-explanation conclusion step"],
  ["Observed traffic is evidence, not authorization", "decision-explanation policy warning"],
  ["Observed evidence", "Observed evidence section"],
  ["Zeek provenance", "Zeek provenance section"],
  ["Detection Context / policy", "Detection Context section"],
  ["Detector inference", "Detector inference section"],
  ["Legitimate context changes", "legitimate context changes section"],
  ["Recommended response", "recommended response section"],
  ["A Zeek observation does not itself create an allowlist", "observed-vs-policy warning"],
].forEach(([needle, label]) => requireText(drawer, needle, label));

[
  ["Why flagged?", "findings-table explanation action"],
  ["confidence", "finding confidence field"],
  ["detectionBasis", "detection-basis field"],
  ["suppressionGuidance", "policy guidance field"],
  ["observed-only", "observed-only provenance label"],
  ["provenanceEvidence", "finding Zeek provenance presentation field"],
  ["authoritative", "authoritative provenance label"],
  ["Zeek-discovered asset alone must remain observed-only", "rogue-device non-authorizing guidance"],
  ["observations\", \"confidence\", \"detection_basis", "CSV confidence/detection-basis columns"],
].forEach(([needle, label]) => requireText(findings, needle, label));

[
  ["Why was this flagged?", "decision-explanation rendering test"],
  ["Why flagged?", "findings-table explanation action test"],
  ["keeps observed evidence separate from authoritative Detection Context policy", "evidence/policy test"],
  ["renders the five explainability sections", "drawer-section test"],
  ["conn.log record 12", "Zeek provenance rendering test"],
  ["degrades gracefully when an older detector finding lacks explainability metadata", "legacy-report test"],
  ["surfaces confidence and detection basis in the findings table", "table/selection test"],
].forEach(([needle, label]) => requireText(tests, needle, label));

console.log("Findings explainability UX contract: PASS");
