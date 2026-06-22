import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import clawStoreContract from "../../../contracts/claw-store/v1/contract.json";
import { api } from "../lib/api";
import type { ClawAvailability, ClawCatalogEntry, ListResponse } from "../lib/types";
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

function listEnvelopeReadyFixture(): ListResponse<ClawCatalogEntry> {
  return clawStoreContract.fixtures.list_envelope_ready as unknown as ListResponse<ClawCatalogEntry>;
}

function listEnvelopeReadyClaw(overrides: Partial<ClawCatalogEntry> = {}): ClawCatalogEntry {
  const [claw] = listEnvelopeReadyFixture().data;
  return {
    ...claw,
    availability: claw.availability ? { ...claw.availability } : undefined,
    ...overrides,
  };
}

function notInstalledAvailability(name: string, base: ClawAvailability | undefined): ClawAvailability | undefined {
  if (!base) return undefined;
  return {
    ...base,
    name,
    install: {
      ...base.install,
      status: "not_installed",
      installed_at: null,
    },
    overall: { state: "not_installed" },
    reasons: [{ type: "not_installed" }],
    degradations: [],
  };
}

describe("ClawStorePage", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("consumes the Rust v1 list fixture with installability and availability", async () => {
    const fixture = listEnvelopeReadyFixture();
    const [claw] = fixture.data;
    expect(claw.installable).toBe(true);
    expect(claw.availability?.name).toBe(claw.name);
    expect(claw.availability?.install.status).toBe("succeeded");
    expect(claw.availability?.overall.state).toBe("creatable");

    mockedApi.listClaws.mockResolvedValue(fixture.data);

    render(<ClawStorePage />);

    expect(await screen.findByText("picoclaw")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "uninstall" })).toBeInTheDocument();
  });

  it("uses backend installable instead of tier to allow install actions", async () => {
    const fixtureClaw = listEnvelopeReadyClaw();
    const name = "detected-installable";
    mockedApi.listClaws.mockResolvedValue([
      listEnvelopeReadyClaw({
        name,
        status: "not_installed",
        tier: "detected",
        installable: true,
        availability: notInstalledAvailability(name, fixtureClaw.availability),
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
    const fixtureClaw = listEnvelopeReadyClaw();
    const name = "supported-unavailable";
    mockedApi.listClaws.mockResolvedValue([
      listEnvelopeReadyClaw({
        name,
        status: "not_installed",
        tier: "supported",
        installable: false,
        unavailable_reason_code: "no_install_plan",
        unavailable_reason: "manifest has no install plan",
        availability: notInstalledAvailability(name, fixtureClaw.availability),
      }),
    ]);

    render(<ClawStorePage />);

    expect(await screen.findByText("manifest has no install plan")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "install" })).not.toBeInTheDocument();
  });
});
