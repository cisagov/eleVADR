import { describe, expect, it, vi } from "vitest";
import {
  DETECTION_ANALYSIS_RESPONSE_CONTRACT_VERSION,
  DEFAULT_DETECTION_ANALYSIS_ENDPOINT,
  isDetectionAnalysisResponse,
  resolveDetectionAnalysisEndpoint,
  submitDetectionAnalysis,
} from "../app/components/DetectionConfiguration/analysisClient";
import { buildDetectionAnalysisRequest } from "../app/components/DetectionConfiguration/analysisRequest";
import { createEmptyProfile } from "../app/components/DetectionConfiguration/profile";

function completedResponse() {
  return {
    contractVersion: DETECTION_ANALYSIS_RESPONSE_CONTRACT_VERSION,
    status: "completed" as const,
    summary: {
      requestedModules: 0,
      completedModules: 0,
      failedModules: 0,
      findingCount: 0,
    },
    moduleResults: [],
    errors: [],
  };
}

describe("DetectionAnalysisClient", () => {
  it("recognizes the versioned response contract", () => {
    expect(isDetectionAnalysisResponse(completedResponse())).toBe(true);
    expect(
      isDetectionAnalysisResponse({
        ...completedResponse(),
        contractVersion: "wrong",
      }),
    ).toBe(false);
  });

  it("resolves a configured Vite endpoint and falls back when blank", () => {
    expect(
      resolveDetectionAnalysisEndpoint(
        " http://127.0.0.1:8765/api/v1/detection-analysis ",
      ),
    ).toBe("http://127.0.0.1:8765/api/v1/detection-analysis");
    expect(resolveDetectionAnalysisEndpoint("   ")).toBe(
      DEFAULT_DETECTION_ANALYSIS_ENDPOINT,
    );
  });

  it("posts the normalized request through one typed boundary", async () => {
    const request = buildDetectionAnalysisRequest(createEmptyProfile());
    const fetchImpl = vi.fn(
      async (_url: RequestInfo | URL, init?: RequestInit) => {
        expect(init?.method).toBe("POST");
        expect(JSON.parse(String(init?.body))).toEqual(request);
        return new Response(JSON.stringify(completedResponse()), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      },
    );

    const result = await submitDetectionAnalysis(request, {
      endpoint: "/test-analysis",
      fetchImpl: fetchImpl as typeof fetch,
    });

    expect(result.status).toBe("completed");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});
