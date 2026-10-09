import { authenticatedFetch } from "./authService";

export interface SavedReportSummary {
  reportId: string;
  title: string;
  sourceFilename: string;
  createdAt: string;
  updatedAt: string;
  reportVersion: string;
  findingCount: number;
  deviceCount: number;
  serviceCount?: number;
  connectionCount?: number;
  captureId: string;
}

function reportsApiUrl(path = ""): string {
  const env = (
    import.meta as ImportMeta & { env?: Record<string, string | undefined> }
  ).env;
  const configured = [
    env?.VITE_PCAP_ANALYSIS_URL,
    env?.VITE_DETECTION_ANALYSIS_URL,
  ]
    .map((value) => value?.trim())
    .find(Boolean);
  if (configured) {
    try {
      return `${new URL(configured, window.location.origin).origin}/api/v1/reports${path}`;
    } catch {
      /* same-origin */
    }
  }
  return `/api/v1/reports${path}`;
}

async function message(response: Response): Promise<string> {
  try {
    const payload = (await response.clone().json()) as { message?: unknown };
    if (typeof payload.message === "string" && payload.message)
      return payload.message;
  } catch {
    /* fallback */
  }
  return `Saved report request failed with status ${response.status}`;
}

export async function listSavedReports(): Promise<SavedReportSummary[]> {
  const response = await authenticatedFetch(reportsApiUrl(), {
    cache: "no-store",
  });
  if (!response.ok) throw new Error(await message(response));
  const payload = (await response.json()) as { reports?: SavedReportSummary[] };
  return Array.isArray(payload.reports) ? payload.reports : [];
}

export async function loadSavedReport(reportId: string): Promise<unknown> {
  const response = await authenticatedFetch(
    reportsApiUrl(`/${encodeURIComponent(reportId)}`),
    { cache: "no-store" },
  );
  if (!response.ok) throw new Error(await message(response));
  const payload = (await response.json()) as { report?: unknown };
  return payload.report;
}

export async function deleteSavedReport(reportId: string): Promise<void> {
  const response = await authenticatedFetch(
    reportsApiUrl(`/${encodeURIComponent(reportId)}`),
    { method: "DELETE" },
  );
  if (!response.ok) throw new Error(await message(response));
}

export async function renameSavedReport(
  reportId: string,
  title: string,
): Promise<SavedReportSummary> {
  const response = await authenticatedFetch(
    reportsApiUrl(`/${encodeURIComponent(reportId)}`),
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title }),
    },
  );
  if (!response.ok) throw new Error(await message(response));
  const payload = (await response.json()) as { report?: SavedReportSummary };
  if (!payload.report)
    throw new Error("Saved report rename returned no report metadata");
  return payload.report;
}
