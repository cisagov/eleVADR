import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { vi, describe, it, expect } from "vitest";
import "@testing-library/jest-dom";
import ExecutiveSummary from "../app/components/ExecutiveSummary/ExecutiveSummary";

describe("ExecutiveSummary (Vitest)", () => {
  it("renders priority findings with cleaned summary text", () => {
    render(
      <ExecutiveSummary
        data={{
          risky_services_alert:
            "Detected <strong>risky</strong> services on the network.",
        }}
      />,
    );

    expect(screen.getByText("Priority Findings")).toBeInTheDocument();
    expect(screen.getByText("Risk-Tagged Services")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(
      screen.getByText("Detected risky services on the network."),
    ).toBeInTheDocument();
  });

  it("scrolls to the mapped panel when View details is clicked", () => {
    const target = document.createElement("div");
    target.id = "service-risk-breakdown-panel";
    document.body.appendChild(target);

    const scrollSpy = vi.spyOn(target, "scrollIntoView");

    render(
      <ExecutiveSummary
        data={{
          risky_services_alert: "Detected risky services.",
        }}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "View details" }));

    expect(scrollSpy).toHaveBeenCalledWith({
      behavior: "smooth",
      block: "start",
    });

    document.body.removeChild(target);
    scrollSpy.mockRestore();
  });

  it("renders the priority findings empty state when no alerts are present", () => {
    render(<ExecutiveSummary data={{}} />);

    expect(screen.getByText("Priority Findings")).toBeInTheDocument();
    expect(
      screen.getByText("No high-priority summary findings were reported."),
    ).toBeInTheDocument();
  });
});
