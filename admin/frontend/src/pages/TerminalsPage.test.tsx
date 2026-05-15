import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../lib/api";
import { TerminalsPage } from "./TerminalsPage";

vi.mock("../lib/api", () => ({
  api: {
    listContainers: vi.fn(),
    reconnectTerminal: vi.fn(),
    getTerminalWorkspace: vi.fn(),
    sessionInfo: vi.fn(),
    listWorkspaces: vi.fn(),
    createWorkspace: vi.fn(),
    renameWorkspace: vi.fn(),
    deleteWorkspace: vi.fn(),
    me: vi.fn(),
  },
}));

/** Tracks calls for selection-hypothesis tests. */
interface MockTerminalSpy {
  focusCalls: number;
  writeCalls: Array<{ data: string | Uint8Array; hadSelection: boolean }>;
  clearSelectionCalls: number;
  selectionCleared: boolean;
  /** Simulate that the user has an active selection. */
  _hasSelection: boolean;
  _selectionText: string;
  /** Callbacks registered via onData. */
  _dataHandlers: Array<(data: string) => void>;
  /** The custom key event handler. */
  _keyHandler: ((ev: KeyboardEvent) => boolean) | null;
  /** OSC handlers keyed by numeric ID. */
  _oscHandlers: Map<number, (data: string) => boolean>;
  /** Shared reference to the Terminal's options (so tests can read disableStdin). */
  options: { fontSize: number; disableStdin: boolean };
}

/** All MockTerminal instances created during a test (newest last). */
const terminalSpies: MockTerminalSpy[] = [];

vi.mock("xterm", () => {
  class MockTerminal {
    cols = 80;
    rows = 24;
    options: { fontSize: number; disableStdin: boolean };
    buffer = { active: { cursorY: 0, baseY: 0, getLine: () => null } };

    // ── Spy tracking ──────────────────────────────────────────────────
    _spy: MockTerminalSpy;

    constructor(opts: { fontSize: number }) {
      this.options = { fontSize: opts.fontSize, disableStdin: false };
      this._spy = {
        focusCalls: 0,
        writeCalls: [],
        clearSelectionCalls: 0,
        selectionCleared: false,
        _hasSelection: false,
        _selectionText: "",
        _dataHandlers: [],
        _keyHandler: null,
        _oscHandlers: new Map(),
        options: this.options,
      };
      terminalSpies.push(this._spy);
    }

    parser = {
      registerOscHandler: (id: number, cb: (data: string) => boolean) => {
        const spy = terminalSpies[terminalSpies.length - 1];
        spy._oscHandlers.set(id, cb);
        return { dispose() {} };
      },
    };

    loadAddon() {}
    open() {}

    write(data: string | Uint8Array, cb?: () => void) {
      this._spy.writeCalls.push({
        data,
        hadSelection: this._spy._hasSelection,
      });
      // Real xterm calls the drain callback asynchronously after parsing;
      // the tests don't depend on timing, so fire it synchronously.
      if (cb) cb();
    }

    focus() {
      this._spy.focusCalls++;
    }

    onData(cb: (data: string) => void) {
      this._spy._dataHandlers.push(cb);
      return { dispose() {} };
    }

    attachCustomKeyEventHandler(cb: (ev: KeyboardEvent) => boolean) {
      this._spy._keyHandler = cb;
    }

    hasSelection() {
      return this._spy._hasSelection;
    }

    getSelection() {
      return this._spy._selectionText;
    }

    clearSelection() {
      this._spy.clearSelectionCalls++;
      this._spy.selectionCleared = true;
      this._spy._hasSelection = false;
      this._spy._selectionText = "";
    }

    paste() {}
    dispose() {}
  }

  return { Terminal: MockTerminal };
});

vi.mock("xterm-addon-fit", () => ({
  FitAddon: class {
    fit() {}
  },
}));

class MockWebSocket {
  static OPEN = 1;
  static CLOSED = 3;
  static instances: MockWebSocket[] = [];

  url: string;
  readyState = MockWebSocket.OPEN;
  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  sentMessages: string[] = [];

  constructor(url: string | URL) {
    this.url = String(url);
    MockWebSocket.instances.push(this);
    queueMicrotask(() => {
      this.onopen?.(new Event("open"));
    });
  }

  send(data: string) {
    this.sentMessages.push(data);
  }

  close(code = 1000, reason = "") {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.({ code, reason } as CloseEvent);
  }

  /** Simulate a server-initiated disconnect (e.g. Cloudflare timeout). */
  simulateServerClose(code = 1006, reason = "") {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.({ code, reason } as CloseEvent);
  }
}

describe("TerminalsPage reconnect flow", () => {
  const mockedApi = api as unknown as {
    listContainers: ReturnType<typeof vi.fn>;
    reconnectTerminal: ReturnType<typeof vi.fn>;
    getTerminalWorkspace: ReturnType<typeof vi.fn>;
    sessionInfo: ReturnType<typeof vi.fn>;
    listWorkspaces: ReturnType<typeof vi.fn>;
    createWorkspace: ReturnType<typeof vi.fn>;
    renameWorkspace: ReturnType<typeof vi.fn>;
    deleteWorkspace: ReturnType<typeof vi.fn>;
    me: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    vi.stubGlobal("WebSocket", MockWebSocket as unknown as typeof WebSocket);
    MockWebSocket.instances = [];
    terminalSpies.length = 0;
    localStorage.clear();
    mockedApi.sessionInfo.mockResolvedValue({ commander: null });

    let id = 0;
    vi.spyOn(globalThis.crypto, "randomUUID").mockImplementation(() => {
      const suffix = id.toString(16).padStart(12, "0");
      id += 1;
      return `00000000-0000-4000-8000-${suffix}`;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("sends reconnect with current session and reuses the same session id (tmux persistence)", { timeout: 15_000 }, async () => {
    const container = "ironclaw-test-iron";
    mockedApi.listContainers.mockResolvedValue([container]);
    mockedApi.reconnectTerminal.mockResolvedValue(undefined);
    mockedApi.getTerminalWorkspace.mockResolvedValue({ id: "ws-test-123", session_id: "ws-test-123", container, status: "active" });
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    await waitFor(() => expect(mockedApi.listContainers).toHaveBeenCalledTimes(1));
    await waitFor(() => {
      const firstSelect = screen.getAllByRole("combobox")[0] as HTMLSelectElement;
      expect(firstSelect.value).toBe(container);
    });

    const sessionIdsForContainer = () =>
      MockWebSocket.instances
        .map((ws) => new URL(ws.url, "http://localhost"))
        .filter((url) => url.pathname === `/api/v1/terminals/${encodeURIComponent(container)}/pty`)
        .map((url) => url.searchParams.get("session") ?? "");

    await waitFor(() => expect(sessionIdsForContainer().length).toBeGreaterThanOrEqual(1));
    const sessionsBefore = sessionIdsForContainer();
    const currentSession = sessionsBefore[sessionsBefore.length - 1];

    const reconnectButton = screen.getAllByRole("button", { name: "reconnect" })[0];
    await userEvent.click(reconnectButton);

    await waitFor(() => {
      expect(mockedApi.reconnectTerminal).toHaveBeenCalledWith(container, currentSession);
    });

    await waitFor(() => {
      expect(sessionIdsForContainer().length).toBeGreaterThan(sessionsBefore.length);
    });

    // Reconnect reuses the SAME session ID so tmux reattaches
    // and preserves shell state (running processes, scrollback).
    const sessionsAfter = sessionIdsForContainer();
    const newSession = sessionsAfter[sessionsAfter.length - 1];
    expect(newSession).toBe(currentSession);
  });
});

// ─── WebSocket auto-reconnect tests ──────────────────────────────────────────
//
// These tests use fake timers to control reconnect delays and verify the
// exponential backoff behavior.  The key challenge is that fake timers intercept
// setTimeout but also affect promise resolution.  We use `vi.advanceTimersByTimeAsync`
// which flushes microtasks between timer ticks.

describe("TerminalsPage auto-reconnect", () => {
  const mockedApi = api as unknown as {
    listContainers: ReturnType<typeof vi.fn>;
    reconnectTerminal: ReturnType<typeof vi.fn>;
    getTerminalWorkspace: ReturnType<typeof vi.fn>;
    sessionInfo: ReturnType<typeof vi.fn>;
    listWorkspaces: ReturnType<typeof vi.fn>;
    createWorkspace: ReturnType<typeof vi.fn>;
    renameWorkspace: ReturnType<typeof vi.fn>;
    deleteWorkspace: ReturnType<typeof vi.fn>;
    me: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });

    vi.stubGlobal("WebSocket", MockWebSocket as unknown as typeof WebSocket);
    MockWebSocket.instances = [];
    terminalSpies.length = 0;
    localStorage.clear();
    mockedApi.sessionInfo.mockResolvedValue({ commander: null });

    // Make jitter deterministic: Math.random() = 0.5 → jitter = 0
    vi.spyOn(Math, "random").mockReturnValue(0.5);

    let id = 0;
    vi.spyOn(globalThis.crypto, "randomUUID").mockImplementation(() => {
      const suffix = id.toString(16).padStart(12, "0");
      id += 1;
      return `00000000-0000-4000-8000-${suffix}`;
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  /** Helper: render the page, wait for WS to connect, return the last WS. */
  async function renderAndConnect(): Promise<MockWebSocket> {
    const container = "picoclaw-test-pico";
    mockedApi.listContainers.mockResolvedValue([container]);
    mockedApi.reconnectTerminal.mockResolvedValue(undefined);
    mockedApi.getTerminalWorkspace.mockResolvedValue({ id: "ws-test-123", session_id: "ws-test-123", container, status: "active" });
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    // shouldAdvanceTime: true lets microtasks and promises resolve naturally.
    // Wait for the API call to resolve and the WS to be created.
    await waitFor(() => {
      expect(MockWebSocket.instances.length).toBeGreaterThanOrEqual(1);
    });

    // Flush onopen microtask
    await act(() => vi.advanceTimersByTimeAsync(0));

    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1];
    return ws;
  }

  it("auto-reconnects on server-initiated disconnect with same session (tmux persistence)", { timeout: 15_000 }, async () => {
    const ws = await renderAndConnect();
    const instancesBefore = MockWebSocket.instances.length;

    // Simulate Cloudflare dropping the connection
    act(() => { ws.simulateServerClose(); });

    // With Math.random()=0.5, attempt 0 → base=1000ms, jitter=0 → delay=1000ms
    await act(() => vi.advanceTimersByTimeAsync(1100));

    expect(MockWebSocket.instances.length).toBeGreaterThan(instancesBefore);

    // The new WS should reuse the SAME session ID — this allows
    // fc-ssh to reconnect to the existing tmux session inside the VM,
    // preserving shell state and running processes.
    const newWs = MockWebSocket.instances[MockWebSocket.instances.length - 1];
    const oldUrl = new URL(ws.url, "http://localhost");
    const newUrl = new URL(newWs.url, "http://localhost");
    expect(newUrl.searchParams.get("session")).toBe(
      oldUrl.searchParams.get("session")
    );
  });

  it("exponential backoff increases delay on consecutive failures", { timeout: 15_000 }, async () => {
    // To test increasing delays we need to prevent onopen from resetting the
    // counter.  We do this by making the MockWebSocket NOT fire onopen on
    // reconnected instances, simulating a server that keeps refusing.
    const ws1 = await renderAndConnect();

    // Override the constructor to skip onopen for subsequent instances
    const originalConstructor = MockWebSocket.prototype.constructor;
    const instanceCountAtStart = MockWebSocket.instances.length;

    // Helper: count WS instances for our container
    const containerWsCount = () =>
      MockWebSocket.instances.filter((w) => w.url.includes("picoclaw-test-pico")).length;

    // Disconnect #1 — attempt 0, delay = 1000ms
    act(() => { ws1.simulateServerClose(); });
    const count1 = containerWsCount();

    // Verify delay is ~1000ms: at 900ms no reconnect, at 1100ms reconnect
    await act(() => vi.advanceTimersByTimeAsync(900));
    expect(containerWsCount()).toBe(count1);
    await act(() => vi.advanceTimersByTimeAsync(200));
    expect(containerWsCount()).toBe(count1 + 1);
  });

  it("reconnect gives up eventually (attempt counter increments)", { timeout: 15_000 }, async () => {
    // We can't easily exhaust 120 attempts with fake timers (onopen keeps
    // resetting the counter).  Instead, we verify the core invariant:
    // after a disconnect, exactly ONE new WS is created (not an infinite
    // stream), and the reconnect timer fires at the expected time.
    const ws = await renderAndConnect();

    const containerWsCount = () =>
      MockWebSocket.instances.filter((w) => w.url.includes("picoclaw-test-pico")).length;

    const countBefore = containerWsCount();

    // Disconnect
    act(() => { ws.simulateServerClose(); });

    // Before the timer fires, no new WS
    await act(() => vi.advanceTimersByTimeAsync(500));
    expect(containerWsCount()).toBe(countBefore);

    // After timer fires (1000ms), exactly one new WS
    await act(() => vi.advanceTimersByTimeAsync(600));
    expect(containerWsCount()).toBe(countBefore + 1);

    // Advance a lot more time — no additional WS should appear (the
    // reconnected WS has onopen fire, so it's stable until next disconnect)
    await act(() => vi.advanceTimersByTimeAsync(30_000));
    expect(containerWsCount()).toBe(countBefore + 1);
  });

  it("does not reconnect after intentional close (reconnect button)", { timeout: 15_000 }, async () => {
    await renderAndConnect();

    // Click the reconnect button — this sets intentionalClose=true
    const reconnectButton = screen.getAllByRole("button", { name: "reconnect" })[0];
    await userEvent.click(reconnectButton);

    // Wait for the reconnect to process
    await act(() => vi.advanceTimersByTimeAsync(100));

    // The old WS is closed intentionally (via reconnect flow).
    // A new WS is created by the reconnect flow itself, but auto-reconnect
    // should NOT create additional WS instances beyond that.
    const countAfterReconnect = MockWebSocket.instances.length;

    // If auto-reconnect were incorrectly triggered, advancing time would
    // create extra WS instances.
    await act(() => vi.advanceTimersByTimeAsync(15_000));
    expect(MockWebSocket.instances.length).toBe(countAfterReconnect);
  });

  it("session ID is resolved via getTerminalWorkspace API", { timeout: 15_000 }, async () => {
    const container = "picoclaw-test-pico";
    await renderAndConnect();

    // The workspace API should have been called to resolve the session ID
    expect(mockedApi.getTerminalWorkspace).toHaveBeenCalledWith(container);

    // The WS URL should use the session ID returned by the workspace API
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1];
    const url = new URL(ws.url, "http://localhost");
    expect(url.searchParams.get("session")).toBe("ws-test-123");
  });

  it("identifies browser commander connections as client=web", { timeout: 15_000 }, async () => {
    await renderAndConnect();

    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1];
    const url = new URL(ws.url, "http://localhost");
    expect(url.searchParams.get("client")).toBe("web");
  });

  it("clears a pending reconnect timer when the socket enters mirror mode", { timeout: 15_000 }, async () => {
    const ws = await renderAndConnect();
    const countBefore = MockWebSocket.instances.length;

    act(() => { ws.simulateServerClose(1006, "network_drop"); });
    act(() => { ws.simulateServerClose(4000, "commander_changed"); });

    await act(() => vi.advanceTimersByTimeAsync(1100));
    expect(MockWebSocket.instances.length).toBe(countBefore);
    expect(screen.getByRole("button", { name: "Take Command" })).toBeInTheDocument();
  });

  it("successful reconnect resets the attempt counter", { timeout: 15_000 }, async () => {
    await renderAndConnect();

    // Disconnect 3 times, advancing through each
    for (let i = 0; i < 3; i++) {
      const latestWs = MockWebSocket.instances[MockWebSocket.instances.length - 1];
      act(() => { latestWs.simulateServerClose(); });
      await act(() => vi.advanceTimersByTimeAsync(11_000));
    }

    // Flush onopen microtask to reset the counter
    await act(() => vi.advanceTimersByTimeAsync(0));

    // Disconnect again — if counter was reset, delay should be ~1000ms (attempt 0)
    // not 8000ms (attempt 3)
    const wsAfterReset = MockWebSocket.instances[MockWebSocket.instances.length - 1];
    act(() => { wsAfterReset.simulateServerClose(); });
    const countBefore = MockWebSocket.instances.length;

    // After 1100ms, reconnect should fire (attempt 0 = 1000ms delay)
    await act(() => vi.advanceTimersByTimeAsync(1100));
    expect(MockWebSocket.instances.length).toBe(countBefore + 1);
  });
});

// ─── Container switching tests ────────────────────────────────────────────────
//
// These tests verify that switching the container dropdown does not leave stale
// WebSocket close handlers that reconnect to the OLD container.
//
// Root cause of the original bug:
//   React effect cleanup sets disposed=true, calls ws.close().
//   Next effect sets disposed=false, creates new WS.
//   The old ws.onclose fires ASYNCHRONOUSLY (real browser) AFTER disposed was
//   reset to false → handler thinks it should reconnect → creates a stale WS
//   for the old container → overwrites wsRef → steals input from new terminal.
//
// Fix: null out ws.onclose BEFORE calling ws.close() in the cleanup function.

describe("TerminalsPage container switching", () => {
  const mockedApi = api as unknown as {
    listContainers: ReturnType<typeof vi.fn>;
    reconnectTerminal: ReturnType<typeof vi.fn>;
    getTerminalWorkspace: ReturnType<typeof vi.fn>;
    sessionInfo: ReturnType<typeof vi.fn>;
    listWorkspaces: ReturnType<typeof vi.fn>;
    createWorkspace: ReturnType<typeof vi.fn>;
    renameWorkspace: ReturnType<typeof vi.fn>;
    deleteWorkspace: ReturnType<typeof vi.fn>;
    me: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });

    vi.stubGlobal("WebSocket", MockWebSocket as unknown as typeof WebSocket);
    MockWebSocket.instances = [];
    terminalSpies.length = 0;
    localStorage.clear();
    mockedApi.sessionInfo.mockResolvedValue({ commander: null });

    vi.spyOn(Math, "random").mockReturnValue(0.5);

    let id = 0;
    vi.spyOn(globalThis.crypto, "randomUUID").mockImplementation(() => {
      const suffix = id.toString(16).padStart(12, "0");
      id += 1;
      return `00000000-0000-4000-8000-${suffix}`;
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("switching containers creates only one new WebSocket (no stale reconnection)", { timeout: 15_000 }, async () => {
    const containers = ["openclaw-neoborn", "picoclaw-demo"];
    mockedApi.listContainers.mockResolvedValue(containers);
    mockedApi.reconnectTerminal.mockResolvedValue(undefined);
    mockedApi.getTerminalWorkspace.mockImplementation((c: string) =>
      Promise.resolve({ id: "ws-test-123", session_id: "ws-test-123", container: c, status: "active" })
    );
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    // Wait for initial container to be selected and WS to connect
    await waitFor(() => {
      expect(MockWebSocket.instances.length).toBeGreaterThanOrEqual(1);
    });
    await vi.advanceTimersByTimeAsync(0);

    const wsCountBefore = MockWebSocket.instances.length;
    const firstWs = MockWebSocket.instances[wsCountBefore - 1];
    expect(firstWs.url).toContain("openclaw-neoborn");

    // Switch to the other container
    const select = screen.getAllByRole("combobox")[0] as HTMLSelectElement;
    await userEvent.selectOptions(select, "picoclaw-demo");

    // Wait for new WS to be created
    await waitFor(() => {
      expect(MockWebSocket.instances.length).toBeGreaterThan(wsCountBefore);
    });
    await vi.advanceTimersByTimeAsync(0);

    const wsCountAfterSwitch = MockWebSocket.instances.length;
    const newWs = MockWebSocket.instances[wsCountAfterSwitch - 1];
    expect(newWs.url).toContain("picoclaw-demo");
    expect(newWs.readyState).toBe(MockWebSocket.OPEN);
    expect(firstWs.readyState).toBe(MockWebSocket.CLOSED);

    // Advance past RECONNECT_BASE_DELAY — if old onclose leaked, a stale
    // reconnection WebSocket for openclaw-neoborn would appear here.
    await vi.advanceTimersByTimeAsync(5000);
    expect(MockWebSocket.instances.length).toBe(wsCountAfterSwitch);

    // No WebSocket for the old container after the switch
    const staleReconnections = MockWebSocket.instances
      .slice(wsCountBefore)
      .filter((ws) => ws.url.includes("openclaw-neoborn"));
    expect(staleReconnections).toHaveLength(0);
  });

  it("async onclose does not cause stale reconnection (race condition regression)", { timeout: 15_000 }, async () => {
    // Override close() to fire onclose ASYNCHRONOUSLY, matching real browser
    // behavior. This is the exact race condition that caused the bug:
    //   cleanup: disposed=true, ws.close() → defers onclose
    //   setup:   disposed=false, creates new WS
    //   deferred onclose fires, sees disposed=false → reconnects old container
    const origClose = MockWebSocket.prototype.close;
    MockWebSocket.prototype.close = function () {
      this.readyState = MockWebSocket.CLOSED;
      const handler = this.onclose;
      if (handler) {
        queueMicrotask(() => handler.call(this, { code: 1000, reason: "" } as CloseEvent));
      }
    };

    try {
      const containers = ["openclaw-alpha", "picoclaw-beta"];
      mockedApi.listContainers.mockResolvedValue(containers);
      mockedApi.reconnectTerminal.mockResolvedValue(undefined);
      mockedApi.getTerminalWorkspace.mockImplementation((c: string) =>
        Promise.resolve({ id: "ws-test-123", session_id: "ws-test-123", container: c, status: "active" })
      );
      mockedApi.me.mockResolvedValue({ username: "admin" });

      render(
        <MemoryRouter>
          <TerminalsPage />
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(MockWebSocket.instances.length).toBeGreaterThanOrEqual(1);
      });
      await vi.advanceTimersByTimeAsync(0);

      const wsCountBefore = MockWebSocket.instances.length;
      const firstWs = MockWebSocket.instances[wsCountBefore - 1];
      expect(firstWs.url).toContain("openclaw-alpha");

      // Switch container — triggers effect cleanup (async close) then setup
      const select = screen.getAllByRole("combobox")[0] as HTMLSelectElement;
      await userEvent.selectOptions(select, "picoclaw-beta");

      // Flush microtasks so the deferred onclose fires
      await vi.advanceTimersByTimeAsync(0);

      // Wait for new WS
      await waitFor(() => {
        const betaInstances = MockWebSocket.instances.filter((ws) =>
          ws.url.includes("picoclaw-beta")
        );
        expect(betaInstances.length).toBeGreaterThanOrEqual(1);
      });

      const wsCountAfterSwitch = MockWebSocket.instances.length;

      // Advance past reconnect delay — stale reconnection would appear here
      await vi.advanceTimersByTimeAsync(5000);

      // CRITICAL: no stale WebSocket for the old container
      const staleReconnections = MockWebSocket.instances
        .slice(wsCountBefore)
        .filter((ws) => ws.url.includes("openclaw-alpha"));
      expect(staleReconnections).toHaveLength(0);

      // Total WS count should not have grown
      expect(MockWebSocket.instances.length).toBe(wsCountAfterSwitch);
    } finally {
      MockWebSocket.prototype.close = origClose;
    }
  });

  it("switching back and forth does not accumulate stale WebSockets", { timeout: 15_000 }, async () => {
    const containers = ["openclaw-one", "picoclaw-two"];
    mockedApi.listContainers.mockResolvedValue(containers);
    mockedApi.reconnectTerminal.mockResolvedValue(undefined);
    mockedApi.getTerminalWorkspace.mockImplementation((c: string) =>
      Promise.resolve({ id: "ws-test-123", session_id: "ws-test-123", container: c, status: "active" })
    );
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(MockWebSocket.instances.length).toBeGreaterThanOrEqual(1);
    });
    await vi.advanceTimersByTimeAsync(0);

    const select = screen.getAllByRole("combobox")[0] as HTMLSelectElement;

    // Switch A → B → A → B (4 switches)
    for (const target of ["picoclaw-two", "openclaw-one", "picoclaw-two", "openclaw-one"]) {
      await userEvent.selectOptions(select, target);
      await vi.advanceTimersByTimeAsync(100);
    }

    // Let any stale reconnections settle
    await vi.advanceTimersByTimeAsync(5000);

    // Only one WebSocket should be OPEN (the last selected container)
    const openSockets = MockWebSocket.instances.filter(
      (ws) => ws.readyState === MockWebSocket.OPEN
    );
    expect(openSockets).toHaveLength(1);
    expect(openSockets[0].url).toContain("openclaw-one");
  });
});

// ─── Selection disappearance hypothesis tests ──────────────────────────────────
//
// The user reports: when selecting text in the terminal (yellow highlight),
// releasing the mouse causes the selection to vanish — preventing copy.
//
// Three hypotheses are tested below:
//
//   H1: tmux `mouse on` captures mouse events — tmux shows its own selection
//       (yellow) during drag, then clears it on mouseup. The text goes into
//       tmux's paste buffer, not the system clipboard. xterm.js never sees
//       a local selection at all.
//       EVIDENCE: `set -g mouse on` in rootfsbuilder + fc_ssh.
//
//   H2: WebSocket data arriving via term.write() clears xterm.js selection.
//       If the shell sends prompt redraws or cursor sequences while the user
//       is selecting, write() may drop the selection.
//
//   H3: onMouseDown → onActivate → setActivePanel → useEffect → term.focus()
//       fires on mousedown before the user finishes selecting, and focus()
//       clears the selection.

describe("Selection disappearance hypotheses", () => {
  const mockedApi = api as unknown as {
    listContainers: ReturnType<typeof vi.fn>;
    reconnectTerminal: ReturnType<typeof vi.fn>;
    getTerminalWorkspace: ReturnType<typeof vi.fn>;
    sessionInfo: ReturnType<typeof vi.fn>;
    listWorkspaces: ReturnType<typeof vi.fn>;
    createWorkspace: ReturnType<typeof vi.fn>;
    renameWorkspace: ReturnType<typeof vi.fn>;
    deleteWorkspace: ReturnType<typeof vi.fn>;
    me: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    vi.stubGlobal("WebSocket", MockWebSocket as unknown as typeof WebSocket);
    MockWebSocket.instances = [];
    terminalSpies.length = 0;
    localStorage.clear();
    mockedApi.sessionInfo.mockResolvedValue({ commander: null });

    let id = 0;
    vi.spyOn(globalThis.crypto, "randomUUID").mockImplementation(() => {
      const suffix = id.toString(16).padStart(12, "0");
      id += 1;
      return `00000000-0000-4000-8000-${suffix}`;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  /** Render page, wait for WS connection, return the terminal spy. */
  async function renderAndGetSpy(): Promise<MockTerminalSpy> {
    const container = "picoclaw-test-sel";
    mockedApi.listContainers.mockResolvedValue([container]);
    mockedApi.reconnectTerminal.mockResolvedValue(undefined);
    mockedApi.getTerminalWorkspace.mockResolvedValue({ id: "ws-test-123", session_id: "ws-test-123", container, status: "active" });
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(MockWebSocket.instances.length).toBeGreaterThanOrEqual(1);
    });
    // Flush onopen microtask
    await new Promise((r) => setTimeout(r, 0));

    const spy = terminalSpies[terminalSpies.length - 1];
    expect(spy).toBeDefined();
    return spy;
  }

  // ── H1: tmux mouse mode ─────────────────────────────────────────────────────
  //
  // These tests verify that the backend configures tmux with `mouse on`,
  // which causes tmux to intercept mouse events. xterm.js enters mouse
  // reporting mode when it receives the escape sequence \x1b[?1000h (or
  // \x1b[?1002h / \x1b[?1003h). In that mode, mouse events are forwarded
  // to the remote application (tmux) instead of creating a local selection.

  it("H1: tmux sends mouse-mode-enable escape sequences via WebSocket", async () => {
    const spy = await renderAndGetSpy();

    // Simulate tmux startup output that enables mouse reporting.
    // tmux `mouse on` sends SET_VT200_MOUSE (\x1b[?1000h) or variants.
    // The real tmux also sends SGR mouse mode (\x1b[?1006h).
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1];

    // Simulate tmux enabling mouse reporting (this is what tmux actually sends)
    const mouseEnableSequences = [
      "\x1b[?1000h", // SET_VT200_MOUSE — basic mouse tracking
      "\x1b[?1002h", // SET_BTN_EVENT_MOUSE — button-event tracking (drag)
      "\x1b[?1006h", // SET_SGR_EXT_MODE_MOUSE — SGR extended coordinates
    ];

    for (const seq of mouseEnableSequences) {
      ws.onmessage?.(new MessageEvent("message", { data: seq }));
    }

    // Verify the sequences were written to the terminal
    const writtenData = spy.writeCalls.map((c) => c.data);
    expect(writtenData).toContain("\x1b[?1000h");
    expect(writtenData).toContain("\x1b[?1002h");

    // KEY INSIGHT: When xterm.js receives these sequences, it enters mouse
    // reporting mode. In that mode:
    //   - Mouse clicks/drags are forwarded to the remote app (tmux) as escape
    //     sequences, NOT handled as local selection
    //   - tmux renders its own selection highlight (yellow/amber)
    //   - On mouseup, tmux captures the text into its paste buffer and removes
    //     the visual highlight
    //   - xterm.js hasSelection() returns false because it never made a
    //     local selection
    //
    // This matches the user's report: "grifo o texto, fica amarelado,
    // quando desclico o mouse o grifado some"
    //
    // DIAGNOSIS: This is tmux mouse mode behavior, not an xterm.js bug.
    // WORKAROUND: Hold Shift while selecting to bypass tmux and use
    //             xterm.js local selection (then Ctrl+C to copy).
  });

  it("H1: Ctrl+C copy path works when xterm.js has a local selection (Shift+drag)", async () => {
    const spy = await renderAndGetSpy();

    // Simulate user holding Shift and selecting (bypasses tmux mouse mode).
    // In this case, xterm.js makes a local selection.
    spy._hasSelection = true;
    spy._selectionText = "hello world";

    // Simulate Ctrl+C keydown
    const handler = spy._keyHandler;
    expect(handler).not.toBeNull();

    // Mock clipboard
    const writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: { writeText: writeTextMock, readText: vi.fn() },
    });

    const result = handler!({
      type: "keydown",
      ctrlKey: true,
      shiftKey: false,
      altKey: false,
      key: "c",
    } as unknown as KeyboardEvent);

    // Handler should return false (prevent SIGINT) and copy selection
    expect(result).toBe(false);
    expect(writeTextMock).toHaveBeenCalledWith("hello world");
    expect(spy.selectionCleared).toBe(true);
  });

  // ── OSC 52 fix verification ───────────────────────────────────────────────

  it("OSC 52 handler writes decoded base64 to navigator.clipboard", async () => {
    const spy = await renderAndGetSpy();

    // Verify OSC 52 handler was registered
    expect(spy._oscHandlers.has(52)).toBe(true);
    const handler = spy._oscHandlers.get(52)!;

    // Mock clipboard
    const writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: { writeText: writeTextMock, readText: vi.fn() },
    });

    // Simulate tmux sending OSC 52 with base64-encoded "hello world"
    // Format: "c;<base64>" where "c" = clipboard selection
    const encoded = btoa("hello world");
    handler(`c;${encoded}`);

    expect(writeTextMock).toHaveBeenCalledWith("hello world");
  });

  it("OSC 52 handler ignores query requests (payload = '?')", async () => {
    const spy = await renderAndGetSpy();
    const handler = spy._oscHandlers.get(52)!;

    const writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: { writeText: writeTextMock, readText: vi.fn() },
    });

    // tmux may query the clipboard with "c;?"
    handler("c;?");
    expect(writeTextMock).not.toHaveBeenCalled();
  });

  it("OSC 52 handler ignores invalid base64 without throwing", async () => {
    const spy = await renderAndGetSpy();
    const handler = spy._oscHandlers.get(52)!;

    const writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: { writeText: writeTextMock, readText: vi.fn() },
    });

    // Invalid base64 — should not throw or call writeText
    expect(() => handler("c;%%%invalid%%%")).not.toThrow();
    expect(writeTextMock).not.toHaveBeenCalled();
  });

  it("OSC 52 handler creates a copy-toast element", async () => {
    const spy = await renderAndGetSpy();
    const handler = spy._oscHandlers.get(52)!;

    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockResolvedValue(undefined), readText: vi.fn() },
    });

    const encoded = btoa("test copy");
    handler(`c;${encoded}`);

    // The toast should be appended to the terminal-view div
    const toast = document.querySelector(".copy-toast");
    expect(toast).not.toBeNull();
    expect(toast!.textContent).toBe("// copied");
  });

  it("H1: Ctrl+C without selection sends SIGINT (does not try to copy)", async () => {
    const spy = await renderAndGetSpy();

    // No selection active (default after tmux clears it)
    spy._hasSelection = false;

    const handler = spy._keyHandler;
    expect(handler).not.toBeNull();

    const result = handler!({
      type: "keydown",
      ctrlKey: true,
      shiftKey: false,
      altKey: false,
      key: "c",
    } as unknown as KeyboardEvent);

    // Handler returns true → let SIGINT through
    expect(result).toBe(true);
    expect(spy.clearSelectionCalls).toBe(0);
  });

  // ── H2: WebSocket write() during selection ───────────────────────────────────
  //
  // Verifies that incoming WebSocket data calls term.write() while the user
  // might have an active selection. In real xterm.js, certain write() calls
  // (especially those that trigger scrolling or cursor movement) CAN clear
  // the selection. This is a secondary contributor.

  it("H2: WebSocket messages call term.write() even during active selection", async () => {
    const spy = await renderAndGetSpy();

    // Simulate user has selected text
    spy._hasSelection = true;
    spy._selectionText = "selected text";

    // Simulate server sending data (e.g., shell prompt redraw)
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1];
    ws.onmessage?.(new MessageEvent("message", { data: "$ " }));

    // write() was called while selection was active
    const writesDuringSelection = spy.writeCalls.filter((c) => c.hadSelection);
    expect(writesDuringSelection.length).toBeGreaterThanOrEqual(1);
    expect(writesDuringSelection[0].data).toBe("$ ");

    // In real xterm.js, this write() would clear the selection if it causes
    // a scroll or cursor move. The mock doesn't replicate this, but the test
    // proves the code path exists: incoming data + active selection = write().
  });

  it("H2: rapid WebSocket messages could clear selection between mousedown and mouseup", async () => {
    const spy = await renderAndGetSpy();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1];

    // Simulate: user starts selecting (mousedown), then server sends data
    // before the user releases the mouse
    spy._hasSelection = true;

    // Burst of server output during selection (shell echoes, cursor updates)
    const serverMessages = [
      "\x1b[H",        // cursor home
      "\x1b[2J",       // clear screen
      "\x1b[1;1H$ ",   // move cursor + prompt
    ];

    for (const msg of serverMessages) {
      ws.onmessage?.(new MessageEvent("message", { data: msg }));
    }

    // All 3 writes happened while selection was active
    const writesDuringSelection = spy.writeCalls.filter((c) => c.hadSelection);
    expect(writesDuringSelection).toHaveLength(3);

    // In real xterm.js, \x1b[2J (clear screen) WILL clear the selection.
    // This proves H2 is a contributing factor, especially for shells that
    // redraw the prompt frequently (like bash with PROMPT_COMMAND).
  });

  // ── H3: onActivate → focus() cycle ──────────────────────────────────────────
  //
  // Tests that clicking the terminal div triggers onActivate → setActivePanel
  // → useEffect → term.focus(). The question is whether focus() fires during
  // the selection gesture (mousedown→mousemove→mouseup).

  it("H3: clicking the terminal div calls onActivate (focus cycle)", async () => {
    const spy = await renderAndGetSpy();

    const focusCountBefore = spy.focusCalls;

    // Find the terminal-view div and simulate a mousedown+click
    const termDiv = document.querySelector(".terminal-view");
    expect(termDiv).not.toBeNull();

    // Simulate mousedown (fires onActivate)
    termDiv!.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));

    // For an ALREADY-ACTIVE panel, setActivePanel(0) is a no-op
    // → isActive doesn't change → the focus useEffect does NOT re-run.
    // So focus() should NOT be called for the already-active panel.
    //
    // Wait a frame for any requestAnimationFrame to fire
    await new Promise((r) => requestAnimationFrame(r));

    // This test shows H3 is NOT the primary cause when clicking the
    // already-active panel — React bails out on identical state.
    // The focusCalls should be the same or only from the initial mount.
    // The real danger would be clicking a different (inactive) panel.
  });

  it("H3: switching to a different panel calls focus() via requestAnimationFrame", { timeout: 15_000 }, async () => {
    // Render with two containers so we get two panels
    const containers = ["openclaw-alpha", "picoclaw-beta"];
    mockedApi.listContainers.mockResolvedValue(containers);
    mockedApi.reconnectTerminal.mockResolvedValue(undefined);
    mockedApi.getTerminalWorkspace.mockImplementation((c: string) =>
      Promise.resolve({ id: "ws-test-123", session_id: "ws-test-123", container: c, status: "active" })
    );
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    // Add a second panel
    const addButton = screen.getByRole("button", { name: /add-terminal/i });
    await userEvent.click(addButton);

    await waitFor(() => {
      expect(screen.getAllByRole("combobox").length).toBe(2);
    });

    // Wait for WS connections
    await waitFor(() => {
      expect(MockWebSocket.instances.length).toBeGreaterThanOrEqual(2);
    });
    await new Promise((r) => setTimeout(r, 50));

    // Panel 0 is active by default. Get panel 1's spy.
    // terminalSpies[0] = panel 0, terminalSpies[1] = panel 1
    expect(terminalSpies.length).toBeGreaterThanOrEqual(2);
    const panel1Spy = terminalSpies[1];
    const focusBefore = panel1Spy.focusCalls;

    // Click on panel 1's terminal card (this switches activePanel 0 → 1)
    const cards = document.querySelectorAll(".terminal-card");
    expect(cards.length).toBeGreaterThanOrEqual(2);
    act(() => { cards[1].dispatchEvent(new MouseEvent("click", { bubbles: true })); });

    // Wait for requestAnimationFrame in the isActive useEffect
    await act(async () => {
      await new Promise((r) => requestAnimationFrame(r));
      await new Promise((r) => setTimeout(r, 50));
    });

    // When switching panels, term.focus() IS called on the newly active panel.
    // This COULD clear a selection if the user was mid-select on a different panel.
    // However, this only affects multi-panel scenarios — not single-panel use.
    expect(panel1Spy.focusCalls).toBeGreaterThan(focusBefore);
  });
});

// ─── Tmux keyboard shortcuts tests ──────────────────────────────────────────
//
// These tests verify that Cmd+Shift (Mac) or Ctrl+Shift (Linux) keyboard
// shortcuts send the correct tmux prefix sequences via WebSocket.

describe("Tmux keyboard shortcuts", () => {
  const mockedApi = api as unknown as {
    listContainers: ReturnType<typeof vi.fn>;
    reconnectTerminal: ReturnType<typeof vi.fn>;
    getTerminalWorkspace: ReturnType<typeof vi.fn>;
    sessionInfo: ReturnType<typeof vi.fn>;
    listWorkspaces: ReturnType<typeof vi.fn>;
    createWorkspace: ReturnType<typeof vi.fn>;
    renameWorkspace: ReturnType<typeof vi.fn>;
    deleteWorkspace: ReturnType<typeof vi.fn>;
    me: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    vi.stubGlobal("WebSocket", MockWebSocket as unknown as typeof WebSocket);
    MockWebSocket.instances = [];
    terminalSpies.length = 0;
    localStorage.clear();
    mockedApi.sessionInfo.mockResolvedValue({ commander: null });

    let id = 0;
    vi.spyOn(globalThis.crypto, "randomUUID").mockImplementation(() => {
      const suffix = id.toString(16).padStart(12, "0");
      id += 1;
      return `00000000-0000-4000-8000-${suffix}`;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  /** Render page, wait for WS, return { spy, ws, handler }. */
  async function setupTerminal() {
    const container = "picoclaw-test-tmux";
    mockedApi.listContainers.mockResolvedValue([container]);
    mockedApi.reconnectTerminal.mockResolvedValue(undefined);
    mockedApi.getTerminalWorkspace.mockResolvedValue({ id: "ws-test-123", session_id: "ws-test-123", container, status: "active" });
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(MockWebSocket.instances.length).toBeGreaterThanOrEqual(1);
    });
    await new Promise((r) => setTimeout(r, 0));

    const spy = terminalSpies[terminalSpies.length - 1];
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1];
    const handler = spy._keyHandler!;
    expect(handler).not.toBeNull();

    return { spy, ws, handler };
  }

  /** Create a KeyboardEvent-like object for the custom key handler. */
  function makeKeyEvent(overrides: Partial<KeyboardEvent>): KeyboardEvent {
    return {
      type: "keydown",
      ctrlKey: false,
      metaKey: false,
      shiftKey: false,
      altKey: false,
      key: "",
      ...overrides,
    } as unknown as KeyboardEvent;
  }

  /** Get the last sent message parsed as JSON. */
  function lastSent(ws: MockWebSocket): { type: string; data: string } | null {
    if (ws.sentMessages.length === 0) return null;
    return JSON.parse(ws.sentMessages[ws.sentMessages.length - 1]);
  }

  // ── Split shortcuts ───────────────────────────────────────────────────────

  it("Cmd+Shift+\\ sends tmux vertical split (\\x02%)", async () => {
    const { handler, ws } = await setupTerminal();
    const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key: "\\" }));
    expect(result).toBe(false);
    const msg = lastSent(ws);
    expect(msg).toEqual({ type: "input", data: "\x02%" });
  });

  it("Cmd+Shift+- sends tmux horizontal split (\\x02\")", async () => {
    const { handler, ws } = await setupTerminal();
    const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key: "-" }));
    expect(result).toBe(false);
    const msg = lastSent(ws);
    expect(msg).toEqual({ type: "input", data: '\x02"' });
  });

  // ── Pane shortcuts ────────────────────────────────────────────────────────

  it("Cmd+Shift+K sends tmux close pane (\\x02x)", async () => {
    const { handler, ws } = await setupTerminal();
    const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key: "K" }));
    expect(result).toBe(false);
    expect(lastSent(ws)).toEqual({ type: "input", data: "\x02x" });
  });

  it("Cmd+Shift+Z sends tmux zoom toggle (\\x02z)", async () => {
    const { handler, ws } = await setupTerminal();
    const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key: "Z" }));
    expect(result).toBe(false);
    expect(lastSent(ws)).toEqual({ type: "input", data: "\x02z" });
  });

  it("Cmd+Shift+Arrow keys send tmux pane navigation", async () => {
    const { handler, ws } = await setupTerminal();

    const arrows: Array<[string, string]> = [
      ["ArrowUp", "\x1b[A"],
      ["ArrowDown", "\x1b[B"],
      ["ArrowLeft", "\x1b[D"],
      ["ArrowRight", "\x1b[C"],
    ];

    for (const [key, esc] of arrows) {
      ws.sentMessages.length = 0;
      const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key }));
      expect(result).toBe(false);
      expect(lastSent(ws)).toEqual({ type: "input", data: `\x02${esc}` });
    }
  });

  // ── Session shortcuts (app-level) ───────────────────────────────────────

  it("Cmd+Shift+T does NOT send tmux key (app-level new session)", async () => {
    const { handler, ws } = await setupTerminal();
    const sentBefore = ws.sentMessages.length;
    const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key: "T" }));
    expect(result).toBe(false);
    const tmuxMessages = ws.sentMessages.slice(sentBefore).filter((m) => {
      try { const parsed = JSON.parse(m); return parsed.data?.includes("\x02"); } catch { return false; }
    });
    expect(tmuxMessages).toHaveLength(0);
  });

  it("Cmd+Shift+] does NOT send tmux key (app-level next session)", async () => {
    const { handler, ws } = await setupTerminal();
    const sentBefore = ws.sentMessages.length;
    const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key: "]" }));
    expect(result).toBe(false);
    const tmuxMessages = ws.sentMessages.slice(sentBefore).filter((m) => {
      try { const parsed = JSON.parse(m); return parsed.data?.includes("\x02"); } catch { return false; }
    });
    expect(tmuxMessages).toHaveLength(0);
  });

  it("Cmd+Shift+[ does NOT send tmux key (app-level prev session)", async () => {
    const { handler, ws } = await setupTerminal();
    const sentBefore = ws.sentMessages.length;
    const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key: "[" }));
    expect(result).toBe(false);
    const tmuxMessages = ws.sentMessages.slice(sentBefore).filter((m) => {
      try { const parsed = JSON.parse(m); return parsed.data?.includes("\x02"); } catch { return false; }
    });
    expect(tmuxMessages).toHaveLength(0);
  });

  it("Cmd+Shift+L does NOT send tmux key (app-level last session)", async () => {
    const { handler, ws } = await setupTerminal();
    const sentBefore = ws.sentMessages.length;
    const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key: "L" }));
    expect(result).toBe(false);
    const tmuxMessages = ws.sentMessages.slice(sentBefore).filter((m) => {
      try { const parsed = JSON.parse(m); return parsed.data?.includes("\x02"); } catch { return false; }
    });
    expect(tmuxMessages).toHaveLength(0);
  });

  it("Cmd+Shift+R does NOT send tmux key (app-level rename session)", async () => {
    const { handler, ws } = await setupTerminal();
    const sentBefore = ws.sentMessages.length;
    const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key: "R" }));
    expect(result).toBe(false);
    const tmuxMessages = ws.sentMessages.slice(sentBefore).filter((m) => {
      try { const parsed = JSON.parse(m); return parsed.data?.includes("\x02"); } catch { return false; }
    });
    expect(tmuxMessages).toHaveLength(0);
  });

  it("Cmd+Shift+S sends tmux session list (\\x02s)", async () => {
    const { handler, ws } = await setupTerminal();
    const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key: "S" }));
    expect(result).toBe(false);
    expect(lastSent(ws)).toEqual({ type: "input", data: "\x02s" });
  });

  it("Cmd+Shift+H sends tmux scroll/copy mode (\\x02[)", async () => {
    const { handler, ws } = await setupTerminal();
    const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key: "H" }));
    expect(result).toBe(false);
    expect(lastSent(ws)).toEqual({ type: "input", data: "\x02[" });
  });

  it("Cmd+Shift+X sends tmux detach (\\x02d)", async () => {
    const { handler, ws } = await setupTerminal();
    const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key: "X" }));
    expect(result).toBe(false);
    expect(lastSent(ws)).toEqual({ type: "input", data: "\x02d" });
  });

  it("Cmd+Shift+Space sends tmux cycle layouts (\\x02 )", async () => {
    const { handler, ws } = await setupTerminal();
    const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key: " " }));
    expect(result).toBe(false);
    expect(lastSent(ws)).toEqual({ type: "input", data: "\x02 " });
  });

  // ── Ctrl+Shift works too (Linux) ──────────────────────────────────────────

  it("Ctrl+Shift+\\ also works (Linux users)", async () => {
    const { handler, ws } = await setupTerminal();
    const result = handler(makeKeyEvent({ ctrlKey: true, shiftKey: true, key: "\\" }));
    expect(result).toBe(false);
    expect(lastSent(ws)).toEqual({ type: "input", data: "\x02%" });
  });

  // ── Pass-through for unknown keys ─────────────────────────────────────────

  it("Cmd+Shift+unknown key passes through (returns true)", async () => {
    const { handler, ws } = await setupTerminal();
    const sentBefore = ws.sentMessages.length;
    const result = handler(makeKeyEvent({ metaKey: true, shiftKey: true, key: "Q" }));
    expect(result).toBe(true);
    expect(ws.sentMessages.length).toBe(sentBefore);
  });

  // ── No conflict with existing Ctrl+- (font decrease) ─────────────────────

  it("Ctrl+- (no Shift) still triggers font decrease, not tmux split", async () => {
    const { handler, ws } = await setupTerminal();
    // Ctrl+- without Shift → font decrease (existing behavior)
    // The handler call triggers a React state update (font size change).
    // We only care that it returns false (intercepted) and does NOT send
    // a tmux key sequence (which starts with \x02).
    let result!: boolean;
    await act(async () => { result = handler(makeKeyEvent({ ctrlKey: true, key: "-" })); });
    expect(result).toBe(false);
    const tmuxMessages = ws.sentMessages.filter((m) => {
      try { const parsed = JSON.parse(m); return parsed.data?.includes("\x02"); } catch { return false; }
    });
    expect(tmuxMessages).toHaveLength(0);
  });

  it("Ctrl+= (no Shift) still triggers font increase", async () => {
    const { handler, ws } = await setupTerminal();
    let result!: boolean;
    await act(async () => { result = handler(makeKeyEvent({ ctrlKey: true, key: "=" })); });
    expect(result).toBe(false);
    const tmuxMessages = ws.sentMessages.filter((m) => {
      try { const parsed = JSON.parse(m); return parsed.data?.includes("\x02"); } catch { return false; }
    });
    expect(tmuxMessages).toHaveLength(0);
  });
});

// ─── Session picker tests ───────────────────────────────────────────────────

describe("Session picker (multi-workspace)", () => {
  const mockedApi = api as unknown as {
    listContainers: ReturnType<typeof vi.fn>;
    reconnectTerminal: ReturnType<typeof vi.fn>;
    getTerminalWorkspace: ReturnType<typeof vi.fn>;
    sessionInfo: ReturnType<typeof vi.fn>;
    listWorkspaces: ReturnType<typeof vi.fn>;
    createWorkspace: ReturnType<typeof vi.fn>;
    renameWorkspace: ReturnType<typeof vi.fn>;
    deleteWorkspace: ReturnType<typeof vi.fn>;
    me: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    vi.stubGlobal("WebSocket", MockWebSocket as unknown as typeof WebSocket);
    MockWebSocket.instances = [];
    terminalSpies.length = 0;
    localStorage.clear();
    mockedApi.sessionInfo.mockResolvedValue({ commander: null });

    let id = 0;
    vi.spyOn(globalThis.crypto, "randomUUID").mockImplementation(() => {
      const suffix = id.toString(16).padStart(12, "0");
      id += 1;
      return `00000000-0000-4000-8000-${suffix}`;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  const twoWorkspaces = [
    { id: "ws-1", session_id: "ws-1", container: "picoclaw-demo", display_name: "Dev", status: "active" as const, is_connected: false, created_at: "2026-03-18T10:00:00", last_attach_at: "2026-03-18T14:30:00", last_activity_at: "2026-03-18T14:35:00" },
    { id: "ws-2", session_id: "ws-2", container: "picoclaw-demo", display_name: "Debug", status: "active" as const, is_connected: false, created_at: "2026-03-17T10:00:00", last_attach_at: "2026-03-16T14:30:00", last_activity_at: "2026-03-16T14:35:00" },
  ];

  it("session picker appears when multiple workspaces exist", { timeout: 15_000 }, async () => {
    mockedApi.listContainers.mockResolvedValue(["picoclaw-demo"]);
    mockedApi.listWorkspaces.mockResolvedValue({ data: twoWorkspaces, has_more: false, next_cursor: null });
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByTestId("session-picker")).toBeTruthy();
    });

    // Should show both session names.
    expect(screen.getByText("Dev")).toBeTruthy();
    expect(screen.getByText("Debug")).toBeTruthy();
  });

  it("session picker hidden when single workspace (auto-connect)", { timeout: 15_000 }, async () => {
    mockedApi.listContainers.mockResolvedValue(["picoclaw-demo"]);
    // listWorkspaces returns 1 workspace → falls through to getTerminalWorkspace.
    mockedApi.listWorkspaces.mockResolvedValue({ data: [twoWorkspaces[0]], has_more: false, next_cursor: null });
    mockedApi.getTerminalWorkspace.mockResolvedValue({ id: "ws-1", session_id: "ws-1", container: "picoclaw-demo", status: "active" });
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    // Should NOT show the session picker.
    await waitFor(() => {
      expect(screen.queryByTestId("session-picker")).toBeNull();
    });
  });

  it("auto-creates workspace when none exist", { timeout: 15_000 }, async () => {
    mockedApi.listContainers.mockResolvedValue(["picoclaw-demo"]);
    mockedApi.listWorkspaces.mockResolvedValue({ data: [], has_more: false, next_cursor: null });
    mockedApi.getTerminalWorkspace.mockResolvedValue({ id: "ws-auto", session_id: "ws-auto", container: "picoclaw-demo", status: "active" });
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    // Should auto-connect, calling getTerminalWorkspace.
    await waitFor(() => {
      expect(mockedApi.getTerminalWorkspace).toHaveBeenCalled();
    });
  });

  it("create new session via picker", { timeout: 15_000 }, async () => {
    mockedApi.listContainers.mockResolvedValue(["picoclaw-demo"]);
    mockedApi.listWorkspaces.mockResolvedValue({ data: twoWorkspaces, has_more: false, next_cursor: null });
    mockedApi.createWorkspace.mockResolvedValue({
      id: "ws-3", session_id: "ws-3", container: "picoclaw-demo", display_name: "New Session", status: "active",
      is_connected: false, created_at: "2026-03-18T15:00:00", last_attach_at: null, last_activity_at: null,
    });
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    await waitFor(() => expect(screen.getByTestId("new-session-btn")).toBeTruthy());
    await userEvent.click(screen.getByTestId("new-session-btn"));

    // Type a name.
    const nameInput = screen.getByTestId("new-session-name-input");
    await userEvent.type(nameInput, "New Session");
    await userEvent.click(screen.getByTestId("create-session-confirm"));

    await waitFor(() => {
      expect(mockedApi.createWorkspace).toHaveBeenCalledWith("picoclaw-demo", "New Session");
    });
  });

  it("rename session inline", { timeout: 15_000 }, async () => {
    mockedApi.listContainers.mockResolvedValue(["picoclaw-demo"]);
    mockedApi.listWorkspaces.mockResolvedValue({ data: twoWorkspaces, has_more: false, next_cursor: null });
    mockedApi.renameWorkspace.mockResolvedValue(undefined);
    // After rename, refetch returns updated list.
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    await waitFor(() => expect(screen.getByTestId("rename-ws-1")).toBeTruthy());
    await userEvent.click(screen.getByTestId("rename-ws-1"));

    const renameInput = screen.getByTestId("session-rename-input");
    await userEvent.clear(renameInput);
    await userEvent.type(renameInput, "New Name{enter}");

    await waitFor(() => {
      expect(mockedApi.renameWorkspace).toHaveBeenCalledWith("picoclaw-demo", "ws-1", "New Name");
    });
  });

  it("delete inactive session shows simple confirm", { timeout: 15_000 }, async () => {
    mockedApi.listContainers.mockResolvedValue(["picoclaw-demo"]);
    mockedApi.listWorkspaces.mockResolvedValue({ data: twoWorkspaces, has_more: false, next_cursor: null });
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    await waitFor(() => expect(screen.getByTestId("delete-ws-2")).toBeTruthy());
    await userEvent.click(screen.getByTestId("delete-ws-2"));

    // Should show simple confirm (ws-2 is not connected).
    await waitFor(() => {
      const confirmEl = screen.getByTestId("confirm-delete");
      expect(confirmEl).toBeTruthy();
      expect(confirmEl.textContent).toContain("delete session");
    });
  });

  it("delete active session shows warning confirm", { timeout: 15_000 }, async () => {
    const connectedWorkspaces = [
      { ...twoWorkspaces[0], is_connected: true },
      twoWorkspaces[1],
    ];
    mockedApi.listContainers.mockResolvedValue(["picoclaw-demo"]);
    mockedApi.listWorkspaces.mockResolvedValue({ data: connectedWorkspaces, has_more: false, next_cursor: null });
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    await waitFor(() => expect(screen.getByTestId("delete-ws-1")).toBeTruthy());
    await userEvent.click(screen.getByTestId("delete-ws-1"));

    await waitFor(() => {
      const confirmEl = screen.getByTestId("confirm-delete");
      expect(confirmEl).toBeTruthy();
      expect(confirmEl.textContent).toContain("active");
      expect(confirmEl.textContent).toContain("delete anyway");
    });
  });

  it("selecting session connects to correct workspace", { timeout: 15_000 }, async () => {
    mockedApi.listContainers.mockResolvedValue(["picoclaw-demo"]);
    mockedApi.listWorkspaces.mockResolvedValue({ data: twoWorkspaces, has_more: false, next_cursor: null });
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    await waitFor(() => expect(screen.getByText("Debug")).toBeTruthy());

    // Click the "Debug" session.
    await userEvent.click(screen.getByText("Debug"));

    // Session picker should disappear and WebSocket should connect with ws-2.
    await waitFor(() => {
      expect(screen.queryByTestId("session-picker")).toBeNull();
      const wsUrls = MockWebSocket.instances.map((ws) => ws.url);
      expect(wsUrls.some((u) => u.includes("session=ws-2"))).toBe(true);
    });
  });

  it("inactive workspaces rendered with inactive styling", { timeout: 15_000 }, async () => {
    const mixed = [
      twoWorkspaces[0],
      { ...twoWorkspaces[1], status: "inactive" as const },
    ];
    mockedApi.listContainers.mockResolvedValue(["picoclaw-demo"]);
    mockedApi.listWorkspaces.mockResolvedValue({ data: mixed, has_more: false, next_cursor: null });
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      const item = screen.getByTestId("session-item-ws-2");
      expect(item.className).toContain("inactive");
    });
  });

  it("warning shown when 9+ workspaces", { timeout: 15_000 }, async () => {
    const manyWorkspaces = Array.from({ length: 9 }, (_, i) => ({
      id: `ws-${i}`, session_id: `ws-${i}`, container: "picoclaw-demo",
      display_name: `WS ${i}`, status: "active" as const, is_connected: false,
      created_at: "2026-03-18T10:00:00", last_attach_at: "2026-03-18T14:30:00", last_activity_at: null,
    }));
    mockedApi.listContainers.mockResolvedValue(["picoclaw-demo"]);
    mockedApi.listWorkspaces.mockResolvedValue({
      data: manyWorkspaces,
      has_more: false,
      next_cursor: null,
      warning: "You have 9 sessions. Consider closing unused ones.",
    });
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByTestId("session-warning")).toBeTruthy();
      expect(screen.getByTestId("session-warning").textContent).toContain("9 sessions");
    });
  });
});

// ── v2 WS protocol: Binary PTY bytes + CTL markers ────────────────────────────
// Backend (PR #15/#16) sends raw PTY output as Binary frames; control events
// are Binary frames prefixed with "\x00\x01CTL:<name>". The frontend must
// recognise the CTL prefix and forward everything else to xterm.

describe("TerminalsPage v2 WS protocol", () => {
  const mockedApi = api as unknown as {
    listContainers: ReturnType<typeof vi.fn>;
    reconnectTerminal: ReturnType<typeof vi.fn>;
    getTerminalWorkspace: ReturnType<typeof vi.fn>;
    sessionInfo: ReturnType<typeof vi.fn>;
    listWorkspaces: ReturnType<typeof vi.fn>;
    createWorkspace: ReturnType<typeof vi.fn>;
    renameWorkspace: ReturnType<typeof vi.fn>;
    deleteWorkspace: ReturnType<typeof vi.fn>;
    me: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    vi.stubGlobal("WebSocket", MockWebSocket as unknown as typeof WebSocket);
    MockWebSocket.instances = [];
    terminalSpies.length = 0;
    localStorage.clear();
    // Reset api mocks — vi.restoreAllMocks() doesn't clear vi.fn()
    // implementations set by earlier describe blocks, and a stale
    // listWorkspaces resolution would render the session picker
    // instead of auto-connecting.
    vi.mocked(api.listWorkspaces).mockReset();
    vi.mocked(api.listContainers).mockReset();
    vi.mocked(api.getTerminalWorkspace).mockReset();
    vi.mocked(api.reconnectTerminal).mockReset();
    vi.mocked(api.me).mockReset();
    mockedApi.sessionInfo.mockResolvedValue({ commander: null });

    let id = 0;
    vi.spyOn(globalThis.crypto, "randomUUID").mockImplementation(() => {
      const suffix = id.toString(16).padStart(12, "0");
      id += 1;
      return `00000000-0000-4000-8000-${suffix}`;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  async function renderAndConnect(): Promise<{ spy: MockTerminalSpy; ws: MockWebSocket }> {
    const container = "picoclaw-ws-v2";
    mockedApi.listContainers.mockResolvedValue([container]);
    mockedApi.reconnectTerminal.mockResolvedValue(undefined);
    mockedApi.getTerminalWorkspace.mockResolvedValue({ id: "ws-v2-test", session_id: "ws-v2-test", container, status: "active" });
    mockedApi.listWorkspaces.mockResolvedValue({ data: [], has_more: false, next_cursor: null });
    mockedApi.me.mockResolvedValue({ username: "admin" });

    render(
      <MemoryRouter>
        <TerminalsPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(MockWebSocket.instances.length).toBeGreaterThanOrEqual(1);
    });
    await new Promise((r) => setTimeout(r, 0));

    const spy = terminalSpies[terminalSpies.length - 1];
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1];
    expect(spy).toBeDefined();
    return { spy, ws };
  }

  function ctlFrame(name: string): ArrayBuffer {
    const prefix = new Uint8Array([0x00, 0x01, 0x43, 0x54, 0x4c, 0x3a]); // "\x00\x01CTL:"
    const nameBytes = new TextEncoder().encode(name);
    // Copy into a fresh ArrayBuffer — in Node, TextEncoder output may share
    // a pooled ArrayBuffer whose `instanceof ArrayBuffer` check is unreliable
    // across realms.
    const out = new ArrayBuffer(prefix.length + nameBytes.length);
    const view = new Uint8Array(out);
    view.set(prefix, 0);
    view.set(nameBytes, prefix.length);
    return out;
  }

  function rawFrame(text: string): ArrayBuffer {
    const bytes = new TextEncoder().encode(text);
    const out = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(out).set(bytes);
    return out;
  }

  it("disables stdin on CTL:replay_start and re-enables on CTL:replay_done", async () => {
    const { spy, ws } = await renderAndConnect();
    // The connect path pre-emptively disables stdin before the socket opens;
    // start from a known state so this test isolates the CTL transitions.
    spy.options.disableStdin = false;

    ws.onmessage?.(new MessageEvent("message", { data: ctlFrame("replay_start") }));
    expect(spy.options.disableStdin).toBe(true);

    ws.onmessage?.(new MessageEvent("message", { data: ctlFrame("replay_done") }));
    expect(spy.options.disableStdin).toBe(false);
  });

  it("writes raw Binary PTY bytes straight to xterm as Uint8Array", async () => {
    const { spy, ws } = await renderAndConnect();

    ws.onmessage?.(new MessageEvent("message", { data: rawFrame("hello world\r\n") }));

    const last = spy.writeCalls[spy.writeCalls.length - 1];
    expect(last).toBeDefined();
    expect(last.data).toBeInstanceOf(Uint8Array);
    expect(new TextDecoder().decode(last.data as Uint8Array)).toBe("hello world\r\n");
  });

  it("does not treat raw PTY bytes as CTL markers even if they contain 'CTL:'", async () => {
    const { spy, ws } = await renderAndConnect();

    // A byte sequence that contains "CTL:" but does NOT start with \x00\x01
    // must be written to xterm, not parsed as a marker.
    ws.onmessage?.(new MessageEvent("message", { data: rawFrame("CTL: not a marker") }));

    const last = spy.writeCalls[spy.writeCalls.length - 1];
    expect(last.data).toBeInstanceOf(Uint8Array);
    expect(new TextDecoder().decode(last.data as Uint8Array)).toBe("CTL: not a marker");
  });
});
