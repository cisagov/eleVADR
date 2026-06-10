/* --------------------------------------------------------------
   Test‑setup file for Vitest + React Testing Library
   -------------------------------------------------------------- */
import "@testing-library/jest-dom";
import { vi } from "vitest";
declare const global: typeof globalThis; // <-- adds the missing name

/* --------------------------------------------------------------
   Global ResizeObserver mock – many UI components (MUI, charts,
   etc.) call `observe`/`unobserve`/`disconnect`.  The stub does
   nothing but satisfies the API.
   -------------------------------------------------------------- */
global.ResizeObserver = class ResizeObserver {
  observe = () => {
    /* no‑op */
  };
  unobserve = () => {
    /* no‑op */
  };
  disconnect = () => {
    /* no‑op */
  };
};

/* --------------------------------------------------------------
   Minimal WebSocket mock – enough for components that open a
   socket, listen for `onmessage`, and close it.
   -------------------------------------------------------------- */
class MockWebSocket {
  public static readonly OPEN = 1;
  public static readonly CLOSED = 3;

  public onmessage: ((event: MessageEvent<string>) => void) | null = null;
  public onerror: ((event: Event) => void) | null = null;
  public readyState = MockWebSocket.OPEN;

  public constructor(public readonly url: string) {}

  public close(): void {
    this.readyState = MockWebSocket.CLOSED;
  }
}

/* expose the mock on the global scope */
Object.defineProperty(globalThis, "WebSocket", {
  writable: true,
  value: MockWebSocket,
});

/* --------------------------------------------------------------
   Stub for `crypto.randomUUID` – the app uses it to generate a
   session‑id for the backend request.
   -------------------------------------------------------------- */
Object.defineProperty(globalThis, "crypto", {
  value: {
    randomUUID: (): string => "test-session-id",
  },
  configurable: true,
});

/* --------------------------------------------------------------
   Mock `window.scrollTo` – Vitest’s `vi.fn()` replaces the Jest
   helper.
   -------------------------------------------------------------- */
Object.defineProperty(globalThis, "scrollTo", {
  value: vi.fn(),
  writable: true,
});

/* --------------------------------------------------------------
   Mock `HTMLElement.prototype.scrollIntoView`.  Using `vi.fn()`
   lets us assert the call in tests.
   -------------------------------------------------------------- */
Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
  value: vi.fn(),
  writable: true,
});
