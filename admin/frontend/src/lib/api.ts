import type { ClawCatalogEntry, CloudflareSetupResponse, CloudflareStatus, CloudflareZone, HostResources, Instance, Job, ListResponse, ListWorkspacesResponse, LogEntry, MaintenanceStatus, NetworkStatus, PublicSitesResponse, User, Workspace } from "./types";

type JsonValue = Record<string, unknown>;

/** Error with HTTP status code preserved for callers to distinguish 401 from 500. */
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {})
    },
    ...init
  });

  if (response.status === 204) {
    return undefined as T;
  }

  // Check status BEFORE parsing JSON — error responses may have no body
  // (e.g. 401 from auth middleware). Parsing first would throw SyntaxError
  // instead of ApiError, breaking status-code detection in callers.
  if (!response.ok) {
    let message = "request failed";
    try {
      const data = (await response.json()) as JsonValue;
      message = String(data.error ?? message);
    } catch {
      // Non-JSON body (e.g. empty 401) — use default message.
    }
    throw new ApiError(message, response.status);
  }
  return (await response.json()) as T;
}

export const api = {
  login: async (username: string, password: string) => {
    await request<{ ok: boolean }>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password })
    });
  },

  logout: async () => {
    await request<void>("/api/v1/auth/logout", { method: "POST" });
  },

  me: async () => {
    return request<User>("/api/v1/me");
  },

  listInstances: async () => {
    const data = await request<ListResponse<Instance>>("/api/v1/instances");
    return data.data;
  },

  createInstance: async (
    name: string,
    clawType: string,
    tools?: string[],
    guestOs?: string,
    cpuCores?: number,
    ramMb?: number,
    diskGb?: number,
  ) => {
    const body: Record<string, unknown> = { name, claw_type: clawType, tools, guest_os: guestOs || "" };
    if (cpuCores != null) body.cpu_cores = cpuCores;
    if (ramMb != null) body.ram_mb = ramMb;
    if (diskGb != null) body.disk_gb = diskGb;
    const data = await request<{ instance: Instance; job_id?: string; message?: string }>("/api/v1/instances", {
      method: "POST",
      body: JSON.stringify(body),
    });
    return data;
  },

  getInstanceStatus: async (id: string) => {
    const data = await request<{ instance: Instance; job?: Job }>(`/api/v1/instances/${encodeURIComponent(id)}/status`);
    return data;
  },

  stopInstance: async (id: string) => {
    await request<void>(`/api/v1/instances/${encodeURIComponent(id)}/stop`, { method: "POST" });
  },

  restartInstance: async (id: string) => {
    await request<void>(`/api/v1/instances/${encodeURIComponent(id)}/restart`, { method: "POST" });
  },

  rebuildInstance: async (id: string) => {
    await request<void>(`/api/v1/instances/${encodeURIComponent(id)}/rebuild`, { method: "POST" });
  },

  deleteInstance: async (id: string) => {
    await request<void>(`/api/v1/instances/${encodeURIComponent(id)}`, { method: "DELETE" });
  },

  getJob: async (jobId: string) => {
    return request<Job>(`/api/v1/jobs/${encodeURIComponent(jobId)}`);
  },

  listLogs: async (limit = 200) => {
    const data = await request<ListResponse<LogEntry>>(`/api/v1/logs?limit=${limit}`);
    return data.data;
  },

  listContainers: async () => {
    const data = await request<ListResponse<string>>("/api/v1/terminals/containers");
    return data.data;
  },

  reconnectTerminal: async (container: string, session?: string) => {
    const sessionQuery = session ? `?session=${encodeURIComponent(session)}` : "";
    await request<void>(`/api/v1/terminals/${encodeURIComponent(container)}/reconnect${sessionQuery}`, {
      method: "POST"
    });
  },

  getTerminalWorkspace: async (container: string) => {
    const data = await request<{
      workspace: {
        id: string;
        session_id: string;
        container: string;
        display_name: string;
        status: string;
      };
    }>(`/api/v1/terminals/${encodeURIComponent(container)}/workspace`, {
      method: "POST"
    });
    return data.workspace;
  },

  getMaintenanceStatus: async () => {
    return request<MaintenanceStatus>("/api/v1/admin/maintenance");
  },

  sessionInfo: async (container: string, session: string) => {
    return request<{ commander: { client_id: string; client_type: string } | null }>(
      `/api/v1/terminals/${encodeURIComponent(container)}/session-info?session=${encodeURIComponent(session)}`
    );
  },

  listWorkspaces: async (container: string) => {
    return request<ListWorkspacesResponse>(
      `/api/v1/terminals/${encodeURIComponent(container)}/workspaces`
    );
  },

  createWorkspace: async (container: string, displayName: string) => {
    const data = await request<{ workspace: Workspace }>(
      `/api/v1/terminals/${encodeURIComponent(container)}/workspaces`,
      { method: "POST", body: JSON.stringify({ display_name: displayName }) }
    );
    return data.workspace;
  },

  renameWorkspace: async (container: string, id: string, displayName: string) => {
    await request<void>(
      `/api/v1/terminals/${encodeURIComponent(container)}/workspaces/${encodeURIComponent(id)}`,
      { method: "PATCH", body: JSON.stringify({ display_name: displayName }) }
    );
  },

  deleteWorkspace: async (container: string, id: string) => {
    await request<void>(
      `/api/v1/terminals/${encodeURIComponent(container)}/workspaces/${encodeURIComponent(id)}`,
      { method: "DELETE" }
    );
  },

  generateQrToken: async (id: string) => {
    return request<{
      token: string;
      expires_at: string;
      qr_host?: string;
      qr_channel?: string;
      deep_link?: string;
      instance: {
        id: string;
        name: string;
        container: string;
        claw_type: string;
      };
    }>(`/api/v1/instances/${encodeURIComponent(id)}/qr-token`, {
      method: "POST"
    });
  },

  getNetworkStatus: async () => {
    return request<NetworkStatus>("/api/v1/network/status");
  },

  listClaws: async () => {
    const data = await request<ListResponse<ClawCatalogEntry>>("/api/v1/claws");
    return data.data;
  },

  installClaw: async (name: string) => {
    return request<{ job_id: string; message: string }>(`/api/v1/claws/${encodeURIComponent(name)}/install`, {
      method: "POST",
    });
  },

  uninstallClaw: async (name: string) => {
    return request<{ job_id: string; message: string }>(`/api/v1/claws/${encodeURIComponent(name)}/uninstall`, {
      method: "POST",
    });
  },

  getResources: async () => {
    return request<HostResources>("/api/v1/admin/resources");
  },

  // ── Public sites (per instance) ──────────────────────────────────────────

  /** Reuses /status — returns the Instance row only. 404 if missing. */
  getInstance: async (id: string) => {
    const data = await request<{ instance: Instance; job?: Job }>(
      `/api/v1/instances/${encodeURIComponent(id)}/status`
    );
    return data.instance;
  },

  listPublicSites: async (id: string) => {
    return request<PublicSitesResponse>(
      `/api/v1/instances/${encodeURIComponent(id)}/public-sites`
    );
  },

  addPublicSite: async (id: string, domain: string, guestPort?: number) => {
    return request<PublicSitesResponse>(
      `/api/v1/instances/${encodeURIComponent(id)}/public-sites`,
      {
        method: "POST",
        body: JSON.stringify({ domain, guest_port: guestPort ?? 3000 }),
      }
    );
  },

  deletePublicSite: async (id: string, domain: string) => {
    return request<{ deleted: boolean; domain: string }>(
      `/api/v1/instances/${encodeURIComponent(id)}/public-sites/${encodeURIComponent(domain)}`,
      { method: "DELETE" }
    );
  },

  // ── Cloudflare admin (Settings → Cloudflare) ────────────────────────────

  cloudflareStatus: async () => {
    return request<CloudflareStatus>("/api/v1/admin/cloudflare/status");
  },

  cloudflareListZones: async (apiToken: string) => {
    return request<{ zones: CloudflareZone[] }>(
      "/api/v1/admin/cloudflare/zones",
      { method: "POST", body: JSON.stringify({ api_token: apiToken }) }
    );
  },

  cloudflareSetup: async (
    apiToken: string,
    accountId: string,
    zoneId: string,
    tunnelName: string,
  ) => {
    return request<CloudflareSetupResponse>(
      "/api/v1/admin/cloudflare/setup",
      {
        method: "POST",
        body: JSON.stringify({
          api_token: apiToken,
          account_id: accountId,
          zone_id: zoneId,
          tunnel_name: tunnelName,
        }),
      }
    );
  },

  cloudflareDisconnect: async () => {
    return request<{
      ok: boolean;
      tunnel_deleted: boolean;
      cnames_attempted: number;
      cnames_deleted: number;
    }>("/api/v1/admin/cloudflare/setup", { method: "DELETE" });
  },
};
