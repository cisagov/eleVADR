import React, { JSX } from "react";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { vi, describe, it, expect } from "vitest";
import { useDrilldown } from "../app/hooks/useDrilldown";

interface TestData {
  value: string;
}

interface HarnessProps {
  fetcher: (key: string) => Promise<TestData>;
}

/**
 * Simple harness component that wires the hook into the UI.
 */
function Harness({ fetcher }: HarnessProps): JSX.Element {
  const drilldown = useDrilldown<TestData, string>(fetcher);

  return (
    <div>
      <button type="button" onClick={() => void drilldown.open("alpha")}>
        Open
      </button>
      <button type="button" onClick={drilldown.close}>
        Close
      </button>

      {/* UI mirrors the hook state – used for assertions */}
      <span data-testid="selected-key">{drilldown.selectedKey ?? "none"}</span>
      <span data-testid="loading">{String(drilldown.isLoading)}</span>
      <span data-testid="error">{drilldown.error ?? "none"}</span>
      <span data-testid="value">{drilldown.data?.value ?? "none"}</span>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*                               TEST SUITE                                   */
/* -------------------------------------------------------------------------- */

describe("useDrilldown (Vitest)", () => {
  it("loads drilldown data for the selected key", async () => {
    const fetcher = vi.fn(async (key: string) => ({
      value: `payload:${key}`,
    }));

    render(<Harness fetcher={fetcher} />);
    fireEvent.click(screen.getByRole("button", { name: "Open" }));

    // Selected key should update immediately
    expect(screen.getByTestId("selected-key")).toHaveTextContent("alpha");

    // Wait for the async fetch to finish and loading to become false
    await waitFor(() => {
      expect(screen.getByTestId("loading")).toHaveTextContent("false");
    });

    // Verify the fetched payload appears
    expect(screen.getByTestId("value")).toHaveTextContent("payload:alpha");
  });

  it("stores a normalized error when the fetcher fails", async () => {
    const fetcher = vi.fn(async () => {
      throw new Error("failed to fetch");
    });

    render(<Harness fetcher={fetcher} />);
    fireEvent.click(screen.getByRole("button", { name: "Open" }));

    // Wait for the error state to be set
    await waitFor(() => {
      expect(screen.getByTestId("error")).toHaveTextContent("failed to fetch");
    });

    // No data should be shown
    expect(screen.getByTestId("value")).toHaveTextContent("none");
  });

  it("clears drilldown state on close", async () => {
    const fetcher = vi.fn(async (key: string) => ({ value: key }));

    render(<Harness fetcher={fetcher} />);

    // Open first – use `act` to avoid React state‑update warnings
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Open" }));
    });

    // Then close
    fireEvent.click(screen.getByRole("button", { name: "Close" }));

    // All hook‑derived UI should be reset
    expect(screen.getByTestId("selected-key")).toHaveTextContent("none");
    expect(screen.getByTestId("value")).toHaveTextContent("none");
    expect(screen.getByTestId("error")).toHaveTextContent("none");
    expect(screen.getByTestId("loading")).toHaveTextContent("false");
  });
});
