import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { vi, describe, it, expect } from "vitest";
import "@testing-library/jest-dom";
import ExecutiveSummary from "../app/components/ExecutiveSummary/ExecutiveSummary";

describe("ExecutiveSummary (Vitest)", () => {
  it("renders formatted alert titles and stripped tooltip text", () => {
    render(
      <ExecutiveSummary
        data={{
          risky_services_alert:
            "Detected <strong>risky</strong> services on the network.",
        }}
      />,
    );

    // Title should be rendered (the component probably formats the key)
    expect(screen.getByText("Risky Services Alert")).toBeInTheDocument();

    // Hover over the 3rd info button (index 2) to show the tooltip
    const infoButtons = screen.getAllByRole("button", { name: "Information" });
    fireEvent.mouseEnter(infoButtons[2]);

    // The tooltip text should be stripped of HTML tags
    expect(
      screen.getByText((content, element) => {
        const hasText =
          element?.textContent === "Detected risky services on the network.";
        const isDeepest =
          element?.firstElementChild === null ||
          element?.firstElementChild?.textContent !==
            "Detected risky services on the network.";
        return hasText && isDeepest;
      }),
    ).toBeInTheDocument();
  });

  it("scrolls to the mapped panel when an alert link is clicked", () => {
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

    // Click the alert link – the component should call target.scrollIntoView(...)
    fireEvent.click(screen.getByRole("link", { name: "Risky Services Alert" }));

    expect(scrollSpy).toHaveBeenCalledWith({
      behavior: "smooth",
      block: "start",
    });

    // Clean‑up
    document.body.removeChild(target);
    scrollSpy.mockRestore();
  });

  it("renders the panel empty state when no alerts are present", () => {
    render(<ExecutiveSummary data={{}} />);

    // The toggle button that expands the panel is a simple “+” button
    const toggleButton = screen.getByText("+");
    fireEvent.click(toggleButton);

    // After expanding, the component should show the empty‑state text
    expect(screen.getByText("No Results")).toBeInTheDocument();
  });
});
