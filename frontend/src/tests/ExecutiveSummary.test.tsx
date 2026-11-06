import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import "@testing-library/jest-dom";
import ExecutiveSummary from "../app/components/ExecutiveSummary/ExecutiveSummary";
import { createMockReport } from "./reportFactory";

describe("ExecutiveSummary", () => {
  it("renders high-priority findings derived from the report", () => {
    const report = createMockReport();
    report.modules.suspicious_outbound_connections_panel[0].count = 20;

    render(<ExecutiveSummary report={report} />);

    expect(screen.getByText("High-Priority Findings")).toBeInTheDocument();

    expect(
      screen.queryByText("No High or Critical findings were reported."),
    ).not.toBeInTheDocument();
  });

  it("opens a finding when Inspect is clicked", () => {
    const report = createMockReport();
    report.modules.suspicious_outbound_connections_panel[0].count = 20;
    const onSelect = vi.fn();

    render(<ExecutiveSummary report={report} onSelect={onSelect} />);

    const inspectButtons = screen.getAllByRole("button", {
      name: "Inspect",
    });

    expect(inspectButtons.length).toBeGreaterThan(0);

    fireEvent.click(inspectButtons[0]);

    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "finding",
      }),
    );
  });

  it("renders the empty state when no high or critical findings exist", () => {
    const report = createMockReport({
      executive_summary: {},
      modules: {
        ...createMockReport().modules,
        service_risk_breakdown_panel: {
          risk_category_counts: {},
          risk_category_services: {},
        },
        suspicious_outbound_connections_panel: [],
      },
    });

    render(<ExecutiveSummary report={report} />);

    expect(
      screen.getByText("No High or Critical findings were reported."),
    ).toBeInTheDocument();
  });
});
