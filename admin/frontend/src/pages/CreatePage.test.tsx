import { render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../lib/api";
import type { ClawCatalogEntry, HostResources } from "../lib/types";
import { CreatePage } from "./CreatePage";

vi.mock("../lib/api", () => ({
  api: {
    listClaws: vi.fn(),
    getResources: vi.fn(),
    createInstance: vi.fn(),
    getJob: vi.fn(),
    getInstanceStatus: vi.fn(),
  },
}));

const mockedApi = api as unknown as {
  listClaws: ReturnType<typeof vi.fn>;
  getResources: ReturnType<typeof vi.fn>;
  createInstance: ReturnType<typeof vi.fn>;
  getJob: ReturnType<typeof vi.fn>;
  getInstanceStatus: ReturnType<typeof vi.fn>;
};

function makeResources(overrides: Partial<HostResources> = {}): HostResources {
  return {
    host: {
      cpu_cores: 16,
      total_ram_mb: 65536,
      available_ram_mb: 65536,
      total_disk_gb: 500,
      available_disk_gb: 500,
    },
    allocated: {
      cpu_cores: 0,
      ram_mb: 0,
      disk_gb: 0,
      instance_count: 0,
      warm_pool_cpu: 0,
      warm_pool_ram_mb: 0,
    },
    budget: {
      cpu_cores: 15,
      ram_mb: 52428,
      cpu_reserve: 1,
      ram_budget_percent: 80,
    },
    available: {
      cpu_cores: 15,
      ram_mb: 52428,
      disk_gb: 500,
    },
    ...overrides,
  };
}

function makeClaw(overrides: Partial<ClawCatalogEntry> = {}): ClawCatalogEntry {
  return {
    name: "picoclaw",
    description: "default claw",
    language: "rust",
    buildable: true,
    version: "1.0.0",
    binary_size_mb: 10,
    min_ram_mb: 512,
    license: "MIT",
    status: "ready",
    ...overrides,
  };
}

describe("CreatePage", () => {
  afterEach(() => {
    vi.clearAllMocks();
    vi.unstubAllGlobals();
  });

  it("builds CPU, RAM, and disk options from live Linux capacity", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ platform: "linux" }),
    }));
    mockedApi.listClaws.mockResolvedValue([makeClaw()]);
    mockedApi.getResources.mockResolvedValue(makeResources({
      available: {
        cpu_cores: 12,
        ram_mb: 24576,
        disk_gb: 120,
      },
      budget: {
        cpu_cores: 12,
        ram_mb: 24576,
        cpu_reserve: 1,
        ram_budget_percent: 80,
      },
    }));

    render(<CreatePage />);

    const cpuSelect = await screen.findByLabelText(/cpu cores/i);
    const ramSelect = await screen.findByLabelText(/ram \(mb\)/i);
    const diskSelect = await screen.findByLabelText(/disk \(gb\)/i);

    await waitFor(() => {
      expect(within(cpuSelect).getByRole("option", { name: "12" })).toBeInTheDocument();
      expect(within(ramSelect).getByRole("option", { name: "24576" })).toBeInTheDocument();
      expect(within(diskSelect).getByRole("option", { name: "120" })).toBeInTheDocument();
    });
  });

  it("keeps macOS runner hard caps even when the host has more resources", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ platform: "macos" }),
    }));
    mockedApi.listClaws.mockResolvedValue([makeClaw()]);
    mockedApi.getResources.mockResolvedValue(makeResources({
      available: {
        cpu_cores: 16,
        ram_mb: 32768,
        disk_gb: 200,
      },
      budget: {
        cpu_cores: 16,
        ram_mb: 32768,
        cpu_reserve: 1,
        ram_budget_percent: 80,
      },
    }));

    render(<CreatePage />);

    const cpuSelect = await screen.findByLabelText(/cpu cores/i);
    const ramSelect = await screen.findByLabelText(/ram \(mb\)/i);

    await waitFor(() => {
      expect(within(cpuSelect).getByRole("option", { name: "4" })).toBeInTheDocument();
      expect(within(ramSelect).getByRole("option", { name: "8192" })).toBeInTheDocument();
    });

    expect(within(cpuSelect).queryByRole("option", { name: "16" })).not.toBeInTheDocument();
    expect(within(ramSelect).queryByRole("option", { name: "32768" })).not.toBeInTheDocument();
  });
});
