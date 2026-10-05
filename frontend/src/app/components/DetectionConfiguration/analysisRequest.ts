import { normalizeProfile } from "./profile";
import { DetectionConfigurationProfile } from "./types";

/**
 * Versioned frontend -> backend analysis contract.
 *
 * The frontend owns Detection Context profile creation, validation, migration,
 * and readiness guidance. It deliberately does NOT compile detector policy
 * namespaces. The backend is the authoritative owner of profile ->
 * AnalysisContext.metadata compilation.
 */
export const DETECTION_ANALYSIS_CONTRACT_VERSION = "elevadr.detection-context.analysis.v1" as const;

export type DetectionAnalysisLogs = Record<string, Array<Record<string, unknown>>>;

export interface DetectionAnalysisRequest {
  contractVersion: typeof DETECTION_ANALYSIS_CONTRACT_VERSION;
  profile: DetectionConfigurationProfile;
  /** Optional Zeek analysis rows. Policy remains exclusively inside profile. */
  logs?: DetectionAnalysisLogs;
}

/**
 * Build the payload that should cross the frontend/backend boundary.
 *
 * Keeping the raw normalized v3 profile as the handoff prevents policy mapping
 * logic from drifting between TypeScript and Python. Scanner observations and
 * explicit site policy remain distinguishable in their original profile fields.
 */
export function buildDetectionAnalysisRequest(
  profile: DetectionConfigurationProfile,
  logs?: DetectionAnalysisLogs,
): DetectionAnalysisRequest {
  const request: DetectionAnalysisRequest = {
    contractVersion: DETECTION_ANALYSIS_CONTRACT_VERSION,
    profile: normalizeProfile(profile),
  };
  if (logs) request.logs = logs;
  return request;
}
