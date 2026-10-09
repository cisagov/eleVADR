import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import NetworkTopology from "../app/components/NetworkTopology/NetworkTopology";
import { ElevadrReport } from "../app/types/Report";
import { InvestigationFilter } from "../app/types/Investigation";
import denseReportJson from "./fixtures/topology_dense_report.json";

const denseReport = denseReportJson as unknown as ElevadrReport;

function installSvgPointerMocks(): void {
  const captures = new Set<number>();
  Object.defineProperty(SVGElement.prototype, "setPointerCapture", {
    configurable: true,
    value(pointerId: number) {
      captures.add(pointerId);
    },
  });
  Object.defineProperty(SVGElement.prototype, "releasePointerCapture", {
    configurable: true,
    value(pointerId: number) {
      captures.delete(pointerId);
    },
  });
  Object.defineProperty(SVGElement.prototype, "hasPointerCapture", {
    configurable: true,
    value(pointerId: number) {
      return captures.has(pointerId);
    },
  });
  Object.defineProperty(SVGElement.prototype, "getBoundingClientRect", {
    configurable: true,
    value() {
      return {
        x: 0,
        y: 0,
        left: 0,
        top: 0,
        right: 1040,
        bottom: 610,
        width: 1040,
        height: 610,
        toJSON: () => ({}),
      };
    },
  });
}

function renderTopology(filters: InvestigationFilter[] = [], drillDown = true) {
  const onFilter = vi.fn();
  const onSelect = vi.fn();
  const onStateChange = vi.fn();
  const rendered = render(
    <NetworkTopology
      report={denseReport}
      filters={filters}
      onFilter={onFilter}
      onSelect={onSelect}
      onStateChange={onStateChange}
    />,
  );
  // Wave 7 starts with aggregate clusters. Drill into the OT cluster before
  // exercising individual-device and connection interactions.
  if (drillDown) {
    const cluster = screen.getByRole("button", { name: /^Expand OT, /i });
    fireEvent.click(cluster);
  }
  return { ...rendered, onFilter, onSelect, onStateChange };
}

function firstDeviceButton(): HTMLElement {
  const button = screen
    .getAllByRole("button")
    .find(
      (item) =>
        / device 10\./.test(item.getAttribute("aria-label") || "") &&
        !(item.getAttribute("aria-label") || "").startsWith("Move device"),
    );
  if (!button) throw new Error("No topology device button was rendered");
  return button;
}

function firstEdgeButton(): HTMLElement {
  const button = screen
    .getAllByRole("button")
    .find((item) =>
      / to .* observations$/.test(item.getAttribute("aria-label") || ""),
    );
  if (!button) throw new Error("No topology edge button was rendered");
  return button;
}

describe("NetworkTopology interaction regression", () => {
  beforeEach(() => {
    localStorage.clear();
    installSvgPointerMocks();
    if (!window.requestAnimationFrame) {
      Object.defineProperty(window, "requestAnimationFrame", {
        configurable: true,
        value: (callback: FrameRequestCallback) =>
          window.setTimeout(() => callback(performance.now()), 0),
      });
      Object.defineProperty(window, "cancelAnimationFrame", {
        configurable: true,
        value: (id: number) => window.clearTimeout(id),
      });
    }
  });

  it("selects a device on click without opening details", () => {
    const { onSelect } = renderTopology();
    const node = firstDeviceButton();
    fireEvent.click(node);
    expect(onSelect).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Inspect details" })).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Filter device/i }),
    ).toBeInTheDocument();
  });

  it("provides contextual inspection and connected-device actions", () => {
    const { onSelect } = renderTopology();
    fireEvent.click(firstDeviceButton());
    expect(onSelect).not.toHaveBeenCalled();
    const inspect = screen.getByRole("button", { name: "Inspect details" });
    fireEvent.click(inspect);
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ type: "device" }));
    fireEvent.click(screen.getByRole("button", { name: "Show connected devices" }));
    expect(screen.getByRole("button", { name: "Show all devices" })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(screen.getByRole("button", { name: "Show all devices" }));
    expect(screen.getByRole("button", { name: "Show connected devices" })).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(screen.getByRole("button", { name: "Clear selection" }));
    expect(screen.queryByRole("button", { name: "Inspect details" })).not.toBeInTheDocument();
    expect(screen.getByText(/Select a device or connection to inspect it/)).toBeInTheDocument();
  });

  it("opens connection details through the widened invisible edge hit target", () => {
    const { onSelect, container } = renderTopology();
    const edge = firstEdgeButton();
    const hitTarget = edge.querySelector(".topology-edge-hit");
    expect(hitTarget).not.toBeNull();
    expect(
      Number(hitTarget?.getAttribute("stroke-width") || 0),
    ).toBeGreaterThanOrEqual(16);
    fireEvent.click(edge);
    expect(onSelect).toHaveBeenCalledWith(
      expect.objectContaining({ type: "connection" }),
    );
    expect(
      container.querySelector(".topology-selection-bar"),
    ).toBeInTheDocument();
  });

  it("keeps filtering explicit and toggles the selected device filter", () => {
    const first = renderTopology();
    fireEvent.click(firstDeviceButton());
    fireEvent.click(screen.getByRole("button", { name: /Filter device/i }));
    expect(first.onFilter).toHaveBeenCalledWith(
      expect.objectContaining({ key: "ip" }),
    );

    const selectedIp = first.onFilter.mock.calls[0]?.[0]?.value as string;
    first.unmount();
    const second = renderTopology([
      { key: "ip", value: selectedIp, label: "Device" },
    ]);
    const matchingNode = screen
      .getAllByRole("button", {
        name: new RegExp(`device ${selectedIp.replaceAll(".", "\\.")}$`, "i"),
      })
      .find((element) => !element.classList.contains("node-drag-handle"));
    if (!matchingNode)
      throw new Error(`No topology device node was rendered for ${selectedIp}`);
    fireEvent.click(matchingNode);
    expect(
      screen.getByRole("button", { name: /Remove device/i }),
    ).toHaveAttribute("aria-pressed", "true");
  });

  it("drags a device from its node body without a move handle", () => {
    const { container, onSelect } = renderTopology();
    const node = firstDeviceButton();
    const svg = container.querySelector("svg[role='img']") as SVGSVGElement;
    expect(node.querySelector(".node-drag-handle")).toBeNull();

    fireEvent.pointerDown(node, { pointerId: 7, clientX: 100, clientY: 100 });
    fireEvent.pointerMove(svg, { pointerId: 7, clientX: 150, clientY: 140 });
    fireEvent.pointerUp(node, { pointerId: 7, clientX: 150, clientY: 140 });
    expect(node.hasPointerCapture(7)).toBe(false);
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("leaves ordinary wheel gestures to page scrolling and reserves modifier-wheel for graph zoom", () => {
    const { container } = renderTopology();
    const svg = container.querySelector("svg[role='img']") as SVGSVGElement;
    const graphLayer = svg.querySelector("g[transform]") as SVGGElement;
    const before = graphLayer.getAttribute("transform");

    fireEvent.wheel(svg, { deltaY: -120, clientX: 520, clientY: 305 });
    expect(graphLayer.getAttribute("transform")).toBe(before);

    fireEvent.wheel(svg, {
      deltaY: -120,
      clientX: 520,
      clientY: 305,
      ctrlKey: true,
    });
    expect(graphLayer.getAttribute("transform")).not.toBe(before);
  });

  it("double-click focuses a node neighborhood and Escape clears selection", () => {
    renderTopology();

    const node = firstDeviceButton();
    fireEvent.doubleClick(node);

    expect(
      screen.getByRole("button", { name: /Filter device/i }),
    ).toBeInTheDocument();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(
      screen.queryByRole("button", { name: /Filter device/i }),
    ).not.toBeInTheDocument();
  });

  it("separates display mode, grouping, and label-density controls", () => {
    renderTopology([], false);
    const view = screen.getByLabelText("Topology view") as HTMLSelectElement;
    for (const mode of ["communication", "findings"]) {
      fireEvent.change(view, { target: { value: mode } });
      expect(view.value).toBe(mode);
    }
    const grouping = screen.getByLabelText("Group by") as HTMLSelectElement;
    for (const mode of ["class", "subnet", "role", "purdue"]) {
      fireEvent.change(grouping, { target: { value: mode } });
      expect(grouping.value).toBe(mode);
    }
    const labels = screen.getByLabelText("Topology label density") as HTMLSelectElement;
    for (const mode of ["minimal", "full", "off"]) {
      fireEvent.change(labels, { target: { value: mode } });
      expect(labels.value).toBe(mode);
    }
  });

  it("supports keyboard cluster drill-down and return to overview", () => {
    renderTopology([], false);
    const cluster = screen.getByRole("button", { name: /^Expand OT, /i });
    expect(cluster).toHaveAttribute("tabindex", "0");
    fireEvent.keyDown(cluster, { key: "Enter" });
    expect(screen.getByRole("button", { name: "Back to overview" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Back to overview" }));
    expect(screen.getByRole("button", { name: /^Expand OT, /i })).toBeInTheDocument();
  });

  it("keeps display options visible and secondary filters collapsible", () => {
    renderTopology([], false);
    const filters = screen.getByText(/^More filters/).closest("summary");
    expect(filters).toHaveAttribute("aria-label", "More topology filters");
    expect(filters?.parentElement?.tagName).toBe("DETAILS");
    expect(screen.getByRole("group", { name: "Topology display options" })).toBeInTheDocument();
    expect(screen.getByLabelText("Topology label density")).toBeVisible();
    expect(screen.getByLabelText("Hide isolated devices")).toBeVisible();
  });

  it("renders aggregate clusters, then retains dense device and edge drill-down", () => {
    const { container } = renderTopology([], false);
    expect(container.querySelectorAll(".topology-aggregate-view [aria-label^='Expand ']").length).toBeGreaterThan(0);
    expect(container.querySelectorAll(".topology-node").length).toBe(0);
    fireEvent.click(screen.getByRole("button", { name: /^Expand OT, /i }));
    expect(container.querySelectorAll(".topology-node").length).toBeGreaterThan(10);
    expect(container.querySelectorAll(".topology-edge").length).toBeGreaterThan(0);
    expect(screen.getByRole("img", { name: /Interactive network topology/i })).toBeInTheDocument();
  });
});
