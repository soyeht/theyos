export type ListResponse<T> = {
  data: T[];
  has_more: boolean;
  next_cursor: string | null;
};

export type User = {
  username: string;
};

export type InstanceStatus = "provisioning" | "active" | "stopped" | "failed";

export type Instance = {
  id: string;
  name: string;
  container: string;
  claw_type: string;
  status: InstanceStatus;
  tokens_24h: number;
  memory_mb: number;
  cpu_pct: number;
  uptime_hours: number;
  auto_update: boolean;
  created_at: string;
  provisioning_message?: string;
  provisioning_error?: string;
  job_id?: string;
  guest_os?: string;
  cpu_cores?: number;
  ram_config_mb?: number;
  disk_gb?: number;
};

export type JobStatus = "pending" | "running" | "completed" | "failed" | "cancelled";

export type Job = {
  id: string;
  type: string;
  status: JobStatus;
  instance_id: string;
  message?: string;
  error?: string;
  actor?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
};

export type LogEntry = {
  id: string;
  level: string;
  component: string;
  message: string;
  at: string;
  actor?: string;
};

export type MaintenanceStatus = {
  maintenance: boolean;
  state: "off" | "draining" | "active";
  reason: string;
  started_at: string;
  retry_after_secs: number;
};

export type WorkspaceStatus = "active" | "inactive";

export type Workspace = {
  id: string;
  session_id: string;
  container: string;
  display_name: string;
  status: WorkspaceStatus;
  is_connected: boolean;
  created_at: string;
  last_attach_at: string | null;
  last_activity_at: string | null;
};

export type ListWorkspacesResponse = ListResponse<Workspace> & {
  warning?: string;
};

export type ChannelStatus = {
  type: string;
  configured: boolean;
  detected: boolean;
  ip?: string;
  hostname?: string;
  has_dns?: boolean;
  has_https?: boolean;
  urls: string[];
  status_detail?: string;
};

export type CaddyStatus = {
  installed: boolean;
  running: boolean;
  admin_url: string;
  status_detail?: string;
};

export type NetworkStatus = {
  channels: ChannelStatus[];
  caddy: CaddyStatus;
};

export type HostResources = {
  host: {
    cpu_cores: number;
    total_ram_mb: number;
    available_ram_mb: number;
    total_disk_gb: number;
    available_disk_gb: number;
  };
  allocated: {
    cpu_cores: number;
    ram_mb: number;
    disk_gb: number;
    instance_count: number;
    warm_pool_cpu: number;
    warm_pool_ram_mb: number;
  };
  budget: {
    cpu_cores: number;
    ram_mb: number;
    cpu_reserve: number;
    ram_budget_percent: number;
  };
  available: {
    cpu_cores: number;
    ram_mb: number;
    disk_gb: number;
  };
};

export type PublicSite = {
  domain: string;
  instance_id: string;
  guest_port: number;
  target_host: string;
  target_port: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
};

export type PublicSiteInstructions = {
  step1: string;
  step2: string;
  step3: string;
  settings_link: string;
  default_guest_port: number;
};

export type CloudflaredWarning = {
  message: string;
  missing: string[];
  config_path: string;
};

export type PublicSitesResponse = {
  sites: PublicSite[];
  instructions: PublicSiteInstructions;
  cloudflared_warning?: CloudflaredWarning;
};

export type ClawInstallStatus = "not_installed" | "installing" | "ready" | "uninstalling" | "failed";

/// Publication / readiness tier of a claw.
/// Mirrors `core_rs::manifest::Tier` — keep in sync.
export type ClawTier = "catalog" | "detected" | "available" | "supported";

export type ClawVerifyStatus = "pending" | "ok" | "failed";

export type ClawCatalogEntry = {
  name: string;
  description: string;
  language: string;
  buildable: boolean;
  version: string;
  binary_size_mb: number;
  min_ram_mb: number;
  license: string;
  status: ClawInstallStatus;
  installed_at?: string;
  job_id?: string;
  error?: string;

  // ── Phase F: catalog tier + provenance ─────────────────────────────────
  tier?: ClawTier;
  stars?: number;
  source?: string;
  last_updated?: string;
  reviewed_upstream_commit?: string;
  latest_upstream_commit?: string;
  install_plan_source?: string;

  // ── Phase E: verify pipeline result ────────────────────────────────────
  verify_status?: ClawVerifyStatus;
  verify_error?: string;
};

// ── Cloudflare admin (Settings → Cloudflare) ───────────────────────────────

export type CloudflareStatus =
  | { configured: false; cloudflared_running: boolean }
  | {
      configured: true;
      cloudflared_running: boolean;
      account_id: string;
      zone_id: string;
      zone_name: string;
      tunnel_id: string;
      tunnel_name: string;
      configured_at: string;
    };

export type CloudflareZone = {
  id: string;
  name: string;
  account_id: string;
  account_name: string;
};

export type CloudflareSetupResponse = {
  ok: boolean;
  account_id: string;
  zone_id: string;
  zone_name: string;
  tunnel_id: string;
  tunnel_name: string;
  configured_at: string;
};
