import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../lib/api";
import type { Instance } from "../lib/types";
import { InstancesPage } from "./InstancesPage";

vi.mock("../lib/api", () => ({
  api: {
    listInstances: vi.fn(),
    stopInstance: vi.fn(),
    restartInstance: vi.fn(),
    rebuildInstance: vi.fn(),
    deleteInstance: vi.fn(),
  },
}));

vi.mock("react-router-dom", async (importOriginal) => {
  const mod = await importOriginal<typeof import("react-router-dom")>();
  return {
    ...mod,
  };
});

const mockedApi = api as unknown as {
  listInstances: ReturnType<typeof vi.fn>;
  stopInstance: ReturnType<typeof vi.fn>;
  restartInstance: ReturnType<typeof vi.fn>;
  rebuildInstance: ReturnType<typeof vi.fn>;
  deleteInstance: ReturnType<typeof vi.fn>;
};

function makeInstance(overrides: Partial<Instance> = {}): Instance {
  return {
    id: "inst-1",
    name: "my-instance",
    container: "picoclaw-my-instance",
    claw_type: "picoclaw",
    status: "active",
    uptime_hours: 5,
    tokens_24h: 100,
    memory_mb: 256,
    cpu_pct: 5.0,
    auto_update: false,
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function renderPage() {
  render(
    <MemoryRouter>
      <InstancesPage />
    </MemoryRouter>
  );
}

describe("InstancesPage", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("shows loading state initially", () => {
    mockedApi.listInstances.mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getByText("loading...")).toBeInTheDocument();
  });

  it("shows 'no instances found' when list is empty", async () => {
    mockedApi.listInstances.mockResolvedValue([]);
    renderPage();
    await waitFor(() => {
      expect(screen.getByText("no instances found")).toBeInTheDocument();
    });
  });

  it("renders instance container id when data is returned", async () => {
    mockedApi.listInstances.mockResolvedValue([makeInstance()]);
    renderPage();
    // Container id is rendered in the instance-id column.
    await waitFor(() => {
      expect(screen.getByText("picoclaw-my-instance")).toBeInTheDocument();
    });
  });

  it("shows error message when listInstances fails", async () => {
    mockedApi.listInstances.mockRejectedValue(new Error("network error"));
    renderPage();
    await waitFor(() => {
      expect(screen.getByText("network error")).toBeInTheDocument();
    });
  });

  it("calls listInstances on mount and sets up a 10-second polling interval", async () => {
    const intervalSpy = vi.spyOn(globalThis, "setInterval");
    mockedApi.listInstances.mockResolvedValue([]);
    renderPage();

    await waitFor(() => expect(mockedApi.listInstances).toHaveBeenCalledTimes(1));

    const pollingCall = intervalSpy.mock.calls.find((args) => args[1] === 10000);
    expect(pollingCall, "setInterval should be called with 10000ms").toBeTruthy();

    intervalSpy.mockRestore();
  });

  it("renders metrics aggregates correctly", async () => {
    mockedApi.listInstances.mockResolvedValue([
      makeInstance({ id: "inst-1", tokens_24h: 300, memory_mb: 512, cpu_pct: 10 }),
      makeInstance({ id: "inst-2", tokens_24h: 200, memory_mb: 256, cpu_pct: 20 }),
    ]);
    renderPage();

    await waitFor(() => {
      // Use within to scope searches to the metrics grid
      const grid = screen.getByText("tokens-24h").closest(".metrics-grid") as HTMLElement;
      expect(within(grid).getByText("500")).toBeInTheDocument();   // totalTokens
      expect(within(grid).getByText("768mb")).toBeInTheDocument(); // totalMemory
      expect(within(grid).getByText("15.0%")).toBeInTheDocument(); // avgCPU
      expect(within(grid).getByText("2")).toBeInTheDocument();     // instance count
    });
  });

  it("calls stopInstance when stop button clicked", async () => {
    mockedApi.listInstances.mockResolvedValue([makeInstance()]);
    mockedApi.stopInstance.mockResolvedValue(undefined);
    renderPage();

    await waitFor(() => expect(screen.getByText("picoclaw-my-instance")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "stop" }));

    await waitFor(() => {
      expect(mockedApi.stopInstance).toHaveBeenCalledWith("inst-1");
    });
  });

  it("calls restartInstance when restart button clicked", async () => {
    mockedApi.listInstances.mockResolvedValue([makeInstance()]);
    mockedApi.restartInstance.mockResolvedValue(undefined);
    renderPage();

    await waitFor(() => expect(screen.getByText("picoclaw-my-instance")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "restart" }));

    await waitFor(() => {
      expect(mockedApi.restartInstance).toHaveBeenCalledWith("inst-1");
    });
  });

  it("calls deleteInstance when delete is confirmed", async () => {
    mockedApi.listInstances.mockResolvedValue([makeInstance()]);
    mockedApi.deleteInstance.mockResolvedValue(undefined);
    renderPage();

    await waitFor(() => expect(screen.getByText("picoclaw-my-instance")).toBeInTheDocument());

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "delete" }));
    await user.click(screen.getByRole("button", { name: "yes" }));

    await waitFor(() => {
      expect(mockedApi.deleteInstance).toHaveBeenCalledWith("inst-1");
    });
  });

  it("calls rebuildInstance when rebuild button clicked", async () => {
    mockedApi.listInstances.mockResolvedValue([makeInstance()]);
    mockedApi.rebuildInstance.mockResolvedValue(undefined);
    renderPage();

    await waitFor(() => expect(screen.getByText("picoclaw-my-instance")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "rebuild" }));

    await waitFor(() => {
      expect(mockedApi.rebuildInstance).toHaveBeenCalledWith("inst-1");
    });
  });

  it("disables action buttons for provisioning instances", async () => {
    mockedApi.listInstances.mockResolvedValue([makeInstance({ status: "provisioning" })]);
    renderPage();

    await waitFor(() => expect(screen.getByText("picoclaw-my-instance")).toBeInTheDocument());

    expect(screen.getByRole("button", { name: "stop" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "restart" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "delete" })).toBeDisabled();
  });

  it("disables rebuild button for provisioning instances", async () => {
    mockedApi.listInstances.mockResolvedValue([makeInstance({ status: "provisioning" })]);
    renderPage();

    await waitFor(() => expect(screen.getByText("picoclaw-my-instance")).toBeInTheDocument());

    expect(screen.getByRole("button", { name: "rebuild" })).toBeDisabled();
  });

  it("enables rebuild button for stopped instances", async () => {
    mockedApi.listInstances.mockResolvedValue([makeInstance({ status: "stopped" })]);
    renderPage();

    await waitFor(() => expect(screen.getByText("picoclaw-my-instance")).toBeInTheDocument());

    expect(screen.getByRole("button", { name: "rebuild" })).not.toBeDisabled();
  });

  it("reloads instances after an action completes", async () => {
    mockedApi.listInstances.mockResolvedValue([makeInstance()]);
    mockedApi.stopInstance.mockResolvedValue(undefined);
    renderPage();

    await waitFor(() => expect(mockedApi.listInstances).toHaveBeenCalledTimes(1));

    await userEvent.click(screen.getByRole("button", { name: "stop" }));

    await waitFor(() => {
      expect(mockedApi.listInstances).toHaveBeenCalledTimes(2);
    });
  });

  // ── pendingAction feedback ─────────────────────────────────────────────

  it("shows 'restarting…' while restart is in-flight, then reverts", async () => {
    let resolve!: () => void;
    mockedApi.listInstances.mockResolvedValue([makeInstance()]);
    mockedApi.restartInstance.mockReturnValue(
      new Promise<void>((res) => { resolve = res; })
    );
    renderPage();
    await waitFor(() => expect(screen.getByText("picoclaw-my-instance")).toBeInTheDocument());

    const user = userEvent.setup();
    void user.click(screen.getByRole("button", { name: "restart" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "restarting…" })).toBeInTheDocument();
    });

    resolve();
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "restart" })).toBeInTheDocument();
    });
  });

  it("shows 'stopping…' while stop is in-flight", async () => {
    mockedApi.listInstances.mockResolvedValue([makeInstance()]);
    mockedApi.stopInstance.mockReturnValue(new Promise<void>(() => {}));
    renderPage();
    await waitFor(() => expect(screen.getByText("picoclaw-my-instance")).toBeInTheDocument());

    const user = userEvent.setup();
    void user.click(screen.getByRole("button", { name: "stop" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "stopping…" })).toBeInTheDocument();
    });
  });

  it("shows 'deleting…' while delete is in-flight", async () => {
    mockedApi.listInstances.mockResolvedValue([makeInstance()]);
    mockedApi.deleteInstance.mockReturnValue(new Promise<void>(() => {}));
    renderPage();
    await waitFor(() => expect(screen.getByText("picoclaw-my-instance")).toBeInTheDocument());

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "delete" }));
    await user.click(screen.getByRole("button", { name: "yes" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "deleting…" })).toBeInTheDocument();
    });
  });

  it("disables all action buttons while an action is pending", async () => {
    mockedApi.listInstances.mockResolvedValue([makeInstance()]);
    mockedApi.restartInstance.mockReturnValue(new Promise<void>(() => {}));
    renderPage();
    await waitFor(() => expect(screen.getByText("picoclaw-my-instance")).toBeInTheDocument());

    const user = userEvent.setup();
    void user.click(screen.getByRole("button", { name: "restart" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "restarting…" })).toBeDisabled();
    });
    expect(screen.getByRole("button", { name: "stop" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "delete" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "rebuild" })).toBeDisabled();
  });

  it("shows error and re-enables buttons when action fails", async () => {
    mockedApi.listInstances.mockResolvedValue([makeInstance()]);
    mockedApi.restartInstance.mockRejectedValue(new Error("VM crashed"));
    renderPage();
    await waitFor(() => expect(screen.getByText("picoclaw-my-instance")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "restart" }));

    await waitFor(() => {
      expect(screen.getByText("VM crashed")).toBeInTheDocument();
    });
    expect(screen.getByRole("button", { name: "restart" })).not.toBeDisabled();
    expect(screen.getByRole("button", { name: "stop" })).not.toBeDisabled();
  });

  it("action on one instance does not disable buttons of another", async () => {
    mockedApi.listInstances.mockResolvedValue([
      makeInstance({ id: "inst-1", name: "alpha", container: "picoclaw-alpha" }),
      makeInstance({ id: "inst-2", name: "beta", container: "picoclaw-beta" }),
    ]);
    mockedApi.restartInstance.mockReturnValue(new Promise<void>(() => {}));
    renderPage();
    await waitFor(() => expect(screen.getByText("picoclaw-alpha")).toBeInTheDocument());

    // Click restart on inst-1 (first row)
    const rows = screen.getAllByRole("button", { name: "restart" });
    const user = userEvent.setup();
    void user.click(rows[0]);

    // inst-1 restart button shows "restarting…"
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "restarting…" })).toBeInTheDocument();
    });

    // inst-2 restart button is still enabled
    expect(screen.getByRole("button", { name: "restart" })).not.toBeDisabled();
  });
});
