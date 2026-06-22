import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../lib/api";
import type { ClawCatalogEntry } from "../lib/types";
import { ClawStorePage } from "./ClawStorePage";

vi.mock("../lib/api", () => ({
  api: {
    listClaws: vi.fn(),
    installClaw: vi.fn(),
    uninstallClaw: vi.fn(),
  },
}));

const mockedApi = api as unknown as {
  listClaws: ReturnType<typeof vi.fn>;
  installClaw: ReturnType<typeof vi.fn>;
  uninstallClaw: ReturnType<typeof vi.fn>;
};

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
    status: "not_installed",
    tier: "supported",
    install_plan_source: "builtin",
    installable: true,
    ...overrides,
  };
}

describe("ClawStorePage", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("uses backend installable instead of tier to allow install actions", async () => {
    mockedApi.listClaws.mockResolvedValue([
      makeClaw({
        name: "detected-installable",
        tier: "detected",
        installable: true,
      }),
    ]);
    mockedApi.installClaw.mockResolvedValue({
      job_id: "job_1234567890abcdef",
      message: "install queued for detected-installable",
    });

    render(<ClawStorePage />);

    const detectedTab = await screen.findByRole("tab", { name: /detected/i });
    await waitFor(() => expect(detectedTab).not.toBeDisabled());
    await userEvent.click(detectedTab);

    await userEvent.click(await screen.findByRole("button", { name: "install" }));

    await waitFor(() => {
      expect(mockedApi.installClaw).toHaveBeenCalledWith("detected-installable");
    });
  });

  it("uses backend unavailable reason when installable is false", async () => {
    mockedApi.listClaws.mockResolvedValue([
      makeClaw({
        name: "supported-unavailable",
        tier: "supported",
        installable: false,
        unavailable_reason_code: "no_install_plan",
        unavailable_reason: "manifest has no install plan",
      }),
    ]);

    render(<ClawStorePage />);

    expect(await screen.findByText("manifest has no install plan")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "install" })).not.toBeInTheDocument();
  });
});
