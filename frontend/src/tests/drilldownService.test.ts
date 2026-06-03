// src/__tests__/drilldownService.test.ts
import {
  fetchFilteredConnections,
  fetchFilteredDevices,
  fetchFilteredServices,
  fetchServiceDrilldown,
} from "../app/services/drilldownService";

import { vi, describe, it, expect, beforeEach } from "vitest";

describe("drilldownService", () => {
  /* Reset any spies/mocks before each test so they don’t leak between cases */
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("builds the service drilldown URL and returns parsed data", async () => {
    const responseBody = {
      report_id: "report-123",
      service_name: "modbus tcp",
      connections: [],
    };

    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => responseBody,
    } as Response);

    const result = await fetchServiceDrilldown("report-123", "modbus tcp", 25);

    expect(result).toEqual(responseBody);
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/reports/report-123/drilldown/service/modbus%20tcp?limit=25",
    );
  });

  it("omits empty filter values when building filtered connection queries", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({
        report_id: "report-123",
        filters: {},
        connections: [],
      }),
    } as Response);

    await fetchFilteredConnections("report-123", {
      service_name: "dns",
      success: true,
      state: "",
      dst_port: null,
      src_ip: undefined,
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/reports/report-123/connections?service_name=dns&success=true",
    );
  });

  it("surfaces backend response text for filtered device errors", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false,
      status: 400,
      text: async () => "Bad device request",
    } as Response);

    await expect(
      fetchFilteredDevices("report-123", { manufacturer: "acme" }),
    ).rejects.toThrow("Bad device request");
  });

  it("falls back to status code when filtered service errors have no body", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false,
      status: 503,
      text: async () => "",
    } as Response);

    await expect(fetchFilteredServices("report-123", {})).rejects.toThrow(
      "Request failed with status 503",
    );
  });
});
