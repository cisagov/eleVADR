// src/__tests__/App.test.tsx
import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "../app/App";
import { createMockReport } from "./reportFactory";
import { vi, describe, it, expect, beforeEach } from "vitest";

/* --------------------------------------------------------------- */
/* Helper – creates a mock `Response` that mimics fetch’s JSON      */
/* response.                                                       */
/* --------------------------------------------------------------- */
function createFetchResponse<TData>(data: TData): Response {
  return {
    ok: true,
    status: 200,
    json: async (): Promise<TData> => data,
    text: async (): Promise<string> => JSON.stringify(data),
  } as Response;
}

/* --------------------------------------------------------------- */
/* Test suite                                                       */
/* --------------------------------------------------------------- */
describe("App", () => {
  // Reset any spies/mocks from previous tests
  beforeEach(() => {
    vi.restoreAllMocks(); // same effect as jest.restoreAllMocks()
  });

  it("renders the initial empty state", () => {
    render(<App />);

    expect(screen.getByText("eleVADR Dashboard")).toBeInTheDocument();
    expect(screen.getByText("Awaiting input...")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run Analysis" })).toBeDisabled();
  });

  it("uploads a pcap and renders dashboard panels from backend data", async () => {
    const report = createMockReport();

    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(createFetchResponse(report));

    render(<App />);

    // ---- simulate file upload ------------------------------------
    const input = screen.getByLabelText("Upload PCAP for Analysis");
    const file = new File(["pcap-bytes"], "capture.pcap", {
      type: "application/vnd.tcpdump.pcap",
    });

    fireEvent.change(input, { target: { files: [file] } });
    fireEvent.click(screen.getByRole("button", { name: "Run Analysis" }));

    // ---- UI that appears after a successful analysis -------------
    expect(await screen.findByText("Executive Summary")).toBeInTheDocument();
    expect(screen.getByText("Service Panel")).toBeInTheDocument();
    expect(screen.getByText("Service Count")).toBeInTheDocument();

    const alertElement = screen.getByText(/Detected/i);
    expect(alertElement.textContent).toBe("Detected risky services.");

    // ---- verify the fetch call ------------------------------------
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      "http://localhost:8000/analyze?session_id=test-session-id",
    );
  });

  it("shows unsupported report version returned by backend", async () => {
    const report = createMockReport({ report_version: "1.9.0" });

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      createFetchResponse(report),
    );

    render(<App />);

    const input = screen.getByLabelText("Upload PCAP for Analysis");
    fireEvent.change(input, {
      target: {
        files: [new File(["pcap-bytes"], "capture.pcap")],
      },
    });
    fireEvent.click(screen.getByRole("button", { name: "Run Analysis" }));

    expect(
      await screen.findByText("Unsupported report version"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/this report uses schema version "1.9.0"/i),
    ).toBeInTheDocument();
  });

  it("surfaces backend errors during analysis", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false,
      status: 500,
      text: async (): Promise<string> => "Backend exploded",
    } as Response);

    render(<App />);

    const input = screen.getByLabelText("Upload PCAP for Analysis");
    fireEvent.change(input, {
      target: {
        files: [new File(["pcap-bytes"], "capture.pcap")],
      },
    });
    fireEvent.click(screen.getByRole("button", { name: "Run Analysis" }));

    expect(
      await screen.findByText("Error during analysis"),
    ).toBeInTheDocument();
    expect(screen.getByText("Backend exploded")).toBeInTheDocument();
  });
});
