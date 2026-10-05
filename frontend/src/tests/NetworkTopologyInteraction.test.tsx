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
    value(pointerId: number) { captures.add(pointerId); },
  });
  Object.defineProperty(SVGElement.prototype, "releasePointerCapture", {
    configurable: true,
    value(pointerId: number) { captures.delete(pointerId); },
  });
  Object.defineProperty(SVGElement.prototype, "hasPointerCapture", {
    configurable: true,
    value(pointerId: number) { return captures.has(pointerId); },
  });
  Object.defineProperty(SVGElement.prototype, "getBoundingClientRect", {
    configurable: true,
    value() {
      return { x: 0, y: 0, left: 0, top: 0, right: 1040, bottom: 610, width: 1040, height: 610, toJSON: () => ({}) };
    },
  });
}

function renderTopology(filters: InvestigationFilter[] = []) {
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
  return { ...rendered, onFilter, onSelect, onStateChange };
}

function firstDeviceButton(): HTMLElement {
  const button = screen.getAllByRole("button").find((item) =>
    / device 10\./.test(item.getAttribute("aria-label") || "") &&
    !(item.getAttribute("aria-label") || "").startsWith("Move device"),
  );
  if (!button) throw new Error("No topology device button was rendered");
  return button;
}

function firstEdgeButton(): HTMLElement {
  const button = screen.getAllByRole("button").find((item) =>
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
        value: (callback: FrameRequestCallback) => window.setTimeout(() => callback(performance.now()), 0),
      });
      Object.defineProperty(window, "cancelAnimationFrame", {
        configurable: true,
        value: (id: number) => window.clearTimeout(id),
      });
    }
  });

  it("opens device details on a normal node-body click without entering drag mode", () => {
    const { onSelect } = renderTopology();
    const node = firstDeviceButton();
    fireEvent.click(node);
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ type: "device" }));
    expect(screen.getByRole("button", { name: /Filter device/i })).toBeInTheDocument();
  });

  it("opens connection details through the widened invisible edge hit target", () => {
    const { onSelect, container } = renderTopology();
    const edge = firstEdgeButton();
    const hitTarget = edge.querySelector(".topology-edge-hit");
    expect(hitTarget).not.toBeNull();
    expect(Number(hitTarget?.getAttribute("stroke-width") || 0)).toBeGreaterThanOrEqual(16);
    fireEvent.click(edge);
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ type: "connection" }));
    expect(container.querySelector(".topology-selection-bar")).toBeInTheDocument();
  });

  it("keeps filtering explicit and toggles the selected device filter", () => {
    const first = renderTopology();
    fireEvent.click(firstDeviceButton());
    fireEvent.click(screen.getByRole("button", { name: /Filter device/i }));
    expect(first.onFilter).toHaveBeenCalledWith(expect.objectContaining({ key: "ip" }));

    const selectedIp = first.onFilter.mock.calls[0]?.[0]?.value as string;
    first.unmount();
    const second = renderTopology([{ key: "ip", value: selectedIp, label: "Device" }]);
    const matchingNode = screen
      .getAllByRole("button", { name: new RegExp(`device ${selectedIp.replaceAll(".", "\\.")}$`, "i") })
      .find((element) => !element.classList.contains("node-drag-handle"));
    if (!matchingNode) throw new Error(`No topology device node was rendered for ${selectedIp}`);
    fireEvent.click(matchingNode);
    expect(screen.getByRole("button", { name: /Remove device/i })).toHaveAttribute("aria-pressed", "true");
  });

  it("uses a dedicated drag handle and exits drag mode on pointer release", () => {
    const { container } = renderTopology();
    const node = firstDeviceButton();
    const moveHandle = node.querySelector<SVGCircleElement>(".node-drag-handle");
    const svg = container.querySelector("svg[role='img']") as SVGSVGElement;
    expect(moveHandle).not.toBeNull();

    fireEvent.pointerDown(moveHandle!, { pointerId: 7, clientX: 100, clientY: 100 });
    fireEvent.pointerMove(svg, { pointerId: 7, clientX: 150, clientY: 140 });
    fireEvent.pointerUp(moveHandle!, { pointerId: 7, clientX: 150, clientY: 140 });

    expect(moveHandle!.hasPointerCapture(7)).toBe(false);
    fireEvent.click(node);
    expect(screen.getByRole("button", { name: /Filter device/i })).toBeInTheDocument();
  });

  it("leaves ordinary wheel gestures to page scrolling and reserves modifier-wheel for graph zoom", () => {
    const { container } = renderTopology();
    const svg = container.querySelector("svg[role='img']") as SVGSVGElement;
    const graphLayer = svg.querySelector("g[transform]") as SVGGElement;
    const before = graphLayer.getAttribute("transform");

    fireEvent.wheel(svg, { deltaY: -120, clientX: 520, clientY: 305 });
    expect(graphLayer.getAttribute("transform")).toBe(before);

    fireEvent.wheel(svg, { deltaY: -120, clientX: 520, clientY: 305, ctrlKey: true });
    expect(graphLayer.getAttribute("transform")).not.toBe(before);
  });

  it("double-click focuses a node neighborhood and Escape clears selection", () => {
    renderTopology();
    const node = firstDeviceButton();
    fireEvent.doubleClick(node);
    expect(screen.getByLabelText("Topology visibility refinements").querySelector("input:disabled")).toBeNull();
    expect(screen.getByRole("button", { name: /Filter device/i })).toBeInTheDocument();

    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("button", { name: /Filter device/i })).not.toBeInTheDocument();
  });

  it("renders all architecture views and label-density modes against the dense fixture", () => {
    renderTopology();
    const view = screen.getByLabelText("Topology view") as HTMLSelectElement;
    for (const mode of ["communication", "subnet", "role", "purdue", "findings"]) {
      fireEvent.change(view, { target: { value: mode } });
      expect(view.value).toBe(mode);
    }
    const labels = screen.getByLabelText("Topology label density") as HTMLSelectElement;
    for (const mode of ["minimal", "full", "off"]) {
      fireEvent.change(labels, { target: { value: mode } });
      expect(labels.value).toBe(mode);
    }
  });

  it("exercises dense-view safeguards without dropping the graph entirely", () => {
    const { container } = renderTopology();
    expect(container.querySelectorAll(".topology-node").length).toBeGreaterThan(40);
    expect(container.querySelectorAll(".topology-edge").length).toBeGreaterThan(20);
    expect(screen.getByRole("img", { name: /Interactive network topology/i })).toBeInTheDocument();
  });
});
