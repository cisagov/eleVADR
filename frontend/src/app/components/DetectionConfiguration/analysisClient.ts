import { DetectionAnalysisRequest } from "./analysisRequest";

export const DETECTION_ANALYSIS_RESPONSE_CONTRACT_VERSION =
  "elevadr.detection-context.analysis-response.v1" as const;

export type DetectionAnalysisStatus = "completed" | "partial" | "failed";

export interface DetectionAnalysisError {
  code: string;
  message: string;
  path?: string;
  moduleId?: string;
}

export interface DetectionModuleFinding {
  title: string;
  severity: string;
  summary: string;
  confidence: string;
  detection_basis: string;
  devices?: string[];
  services?: string[];
  ports?: number[];
  connection_pairs?: Array<Record<string, unknown>>;
  flows?: Array<Record<string, unknown>>;
  subnets?: string[];
  timestamps?: Array<number | string>;
  tags?: string[];
  metadata?: Record<string, unknown>;
  provenance?: { schema_version?: number; resolution?: string; sources?: Array<Record<string, unknown>> };
  [key: string]: unknown;
}

export interface DetectionModuleResult {
  module_id: string;
  findings: DetectionModuleFinding[];
  metrics: Record<string, unknown>;
  evidence: Record<string, unknown>;
  warnings: string[];
}

export interface DetectionAnalysisResponse {
  contractVersion: typeof DETECTION_ANALYSIS_RESPONSE_CONTRACT_VERSION;
  status: DetectionAnalysisStatus;
  summary: {
    requestedModules: number;
    completedModules: number;
    failedModules: number;
    findingCount: number;
  };
  moduleResults: DetectionModuleResult[];
  errors: DetectionAnalysisError[];
}

export interface DetectionAnalysisClientOptions {
  endpoint?: string;
  signal?: AbortSignal;
  fetchImpl?: typeof fetch;
}

export const DEFAULT_DETECTION_ANALYSIS_ENDPOINT = "/api/v1/detection-analysis";

/**
 * Resolve the analysis endpoint from Vite configuration.
 *
 * An explicit endpoint passed to submitDetectionAnalysis always wins. A blank
 * VITE_DETECTION_ANALYSIS_URL intentionally falls back to the same-origin
 * production-friendly default.
 */
export function resolveDetectionAnalysisEndpoint(
  configuredEndpoint: string | undefined = import.meta.env.VITE_DETECTION_ANALYSIS_URL,
): string {
  const value = configuredEndpoint?.trim();
  return value || DEFAULT_DETECTION_ANALYSIS_ENDPOINT;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isDetectionAnalysisResponse(value: unknown): value is DetectionAnalysisResponse {
  if (!isObject(value)) return false;
  if (value.contractVersion !== DETECTION_ANALYSIS_RESPONSE_CONTRACT_VERSION) return false;
  if (!["completed", "partial", "failed"].includes(String(value.status))) return false;
  if (!isObject(value.summary)) return false;
  if (!Array.isArray(value.moduleResults) || !Array.isArray(value.errors)) return false;
  return ["requestedModules", "completedModules", "failedModules", "findingCount"].every(
    (key) => typeof value.summary[key] === "number",
  );
}

/**
 * Typed frontend boundary for future production integration.
 *
 * Detection Context remains transport-independent. The production app can pass
 * an alternate endpoint or fetch implementation without importing backend code.
 */
export async function submitDetectionAnalysis(
  request: DetectionAnalysisRequest,
  options: DetectionAnalysisClientOptions = {},
): Promise<DetectionAnalysisResponse> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const endpoint = options.endpoint ?? resolveDetectionAnalysisEndpoint();
  const response = await fetchImpl(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
    signal: options.signal,
  });

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Analysis service returned non-JSON HTTP ${response.status}`);
  }

  if (!isDetectionAnalysisResponse(payload)) {
    throw new Error("Analysis service returned an unsupported response contract");
  }

  if (!response.ok && payload.status !== "failed") {
    throw new Error(`Analysis service returned HTTP ${response.status}`);
  }

  return payload;
}
