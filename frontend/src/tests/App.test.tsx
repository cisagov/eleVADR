import React from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";
import App from "../app/App";
import { createMockReport } from "./reportFactory";
import { vi, describe, it, expect, beforeEach } from "vitest";

vi.mock("../app/services/authService", () => ({
  AUTH_EXPIRED_EVENT: "elevadr-auth-expired",
  fetchAuthState: vi.fn().mockResolvedValue({
    authEnabled: false,
    user: {
      id: "",
      username: "",
      authenticated: false,
      role: "anonymous",
    },
  }),
  login: vi.fn(),
  logout: vi.fn(),
  authenticatedFetch: vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
    fetch(input, init),
  ),
}));

function reportFile(report: unknown): File {
  return new File([JSON.stringify(report)], "report.json", {
    type: "application/json",
  });
}

describe("App", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the initial welcome state", async () => {
    render(<App />);

    expect(
      await screen.findByRole("heading", { name: "eleVADR Welcome" }),
    ).toBeInTheDocument();

    expect(
      screen.getByText("Open a report or packet capture"),
    ).toBeInTheDocument();

    expect(
      screen.getByLabelText("Open PCAP or JSON report"),
    ).toBeInTheDocument();
  });

  it("opens a JSON report and renders report content", async () => {
    const report = createMockReport();

    render(<App />);

    const input = await screen.findByLabelText("Open PCAP or JSON report");

    fireEvent.change(input, {
      target: {
        files: [reportFile(report)],
      },
    });

    const reportNavigation = await screen.findByRole("navigation", {
      name: "Report sections",
    });

    expect(
      within(reportNavigation).getByRole("button", { name: "Summary" }),
    ).toBeInTheDocument();

    expect(
      within(reportNavigation).getByRole("button", {
        name: /^Findings\d+$/,
      }),
    ).toBeInTheDocument();
  });

  it("loads a v1 JSON report in compatibility mode", async () => {
    const report = createMockReport({
      report_version: "1.9.0",
    });

    render(<App />);

    const input = await screen.findByLabelText("Open PCAP or JSON report");

    fireEvent.change(input, {
      target: {
        files: [reportFile(report)],
      },
    });

    expect(
      await screen.findByLabelText("Legacy report compatibility"),
    ).toBeInTheDocument();

    expect(
      screen.getByText("Loaded in compatibility mode"),
    ).toBeInTheDocument();

    expect(screen.getByText("1.9.0")).toBeInTheDocument();
    expect(screen.getByText("2.0.0")).toBeInTheDocument();
  });

  it("surfaces invalid JSON report errors", async () => {
    render(<App />);

    const input = await screen.findByLabelText("Open PCAP or JSON report");

    const invalidReport = new File(["not-json"], "broken.json", {
      type: "application/json",
    });

    fireEvent.change(input, {
      target: {
        files: [invalidReport],
      },
    });

    expect(
      await screen.findByText(/invalid|failed|could not/i),
    ).toBeInTheDocument();
  });
});
