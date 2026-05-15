import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import { TierBadge } from "../components/TierBadge";
import type { ClawCatalogEntry, ClawInstallStatus, ClawTier } from "../lib/types";

const TIER_TABS: readonly ClawTier[] = ["supported", "available", "detected", "catalog"] as const;

function statusColor(status: ClawInstallStatus): string {
  switch (status) {
    case "ready": return "#22c55e";
    case "installing":
    case "uninstalling": return "#f59e0b";
    case "failed": return "#ef4444";
    default: return "var(--text-muted)";
  }
}

function statusDot(status: ClawInstallStatus): string {
  switch (status) {
    case "ready": return "\u25cf";
    case "installing":
    case "uninstalling": return "\u25cb";
    default: return "\u2013";
  }
}

function statusLabel(status: ClawInstallStatus): string {
  return status.replace("_", " ");
}

function langColor(lang: string): string {
  switch (lang) {
    case "go": return "#00add8";
    case "rust": return "#dea584";
    case "python": return "#3776ab";
    case "node": return "#68a063";
    case "zig": return "#f7a41d";
    default: return "var(--text-muted)";
  }
}

/// True iff the reviewed commit and the latest observed commit disagree.
/// Only surface drift when both SHAs are populated — otherwise we'd render
/// a false positive the first time Discovery runs against a new repo.
function hasDrift(claw: ClawCatalogEntry): boolean {
  const reviewed = claw.reviewed_upstream_commit?.trim() ?? "";
  const latest = claw.latest_upstream_commit?.trim() ?? "";
  return reviewed.length > 0 && latest.length > 0 && reviewed !== latest;
}

/// Short SHA (7 chars), for drift tooltip.
function short(sha?: string): string {
  if (!sha) return "-";
  return sha.trim().slice(0, 7) || "-";
}

function tierOf(claw: ClawCatalogEntry): ClawTier {
  return claw.tier ?? "supported";
}

/// Whether the install button should fire for this row. Matches the
/// invariant encoded in `core_rs::manifest::Tier::can_user_install()`:
/// only `supported` and `available` can be installed from the UI.
/// `buildable` is not required — `available` claws use template-driven
/// build-from-plan and have `buildable: false`, but they are installable.
function canInstallFromUI(claw: ClawCatalogEntry): boolean {
  const t = tierOf(claw);
  return t === "supported" || t === "available";
}

function ClawCard({
  claw,
  onInstall,
  onUninstall,
  busy,
}: {
  claw: ClawCatalogEntry;
  onInstall: (name: string) => void;
  onUninstall: (name: string) => void;
  busy: boolean;
}) {
  const isTransitional = claw.status === "installing" || claw.status === "uninstalling";
  const tier = tierOf(claw);
  const drift = hasDrift(claw);
  const availableSlowWarning = tier === "available" && claw.status === "not_installed";

  return (
    <div className="network-card">
      <div className="network-card-header">
        <span className="network-status-dot" style={{ color: statusColor(claw.status) }}>
          {statusDot(claw.status)}
        </span>
        <strong>{claw.name}</strong>
        <span className="claw-lang-badge" style={{ borderColor: langColor(claw.language), color: langColor(claw.language) }}>
          {claw.language}
        </span>
        <span style={{ marginLeft: "6px" }}>
          <TierBadge tier={tier} />
        </span>
        {drift && (
          <span
            aria-label="drift detected"
            title={`drift detected — reviewed=${short(claw.reviewed_upstream_commit)} latest=${short(claw.latest_upstream_commit)}`}
            style={{
              marginLeft: "6px",
              color: "#f59e0b",
              fontSize: "10px",
              cursor: "help",
              userSelect: "none",
            }}
          >
            {"\u26A0"}
          </span>
        )}
      </div>

      <div className="network-card-body">
        <p className="network-detail muted">{claw.description}</p>
        <p className="network-detail">
          <span className="network-label">status</span>
          <span>{statusLabel(claw.status)}</span>
          {isTransitional && <span className="spinner" />}
        </p>
        {claw.version && (
          <p className="network-detail">
            <span className="network-label">version</span>
            <span>{claw.version}</span>
          </p>
        )}
        <p className="network-detail">
          <span className="network-label">size</span>
          <span>{claw.binary_size_mb >= 1024 ? `${(claw.binary_size_mb / 1024).toFixed(1)} GB` : `${claw.binary_size_mb} MB`}</span>
        </p>
        <p className="network-detail">
          <span className="network-label">min ram</span>
          <span>{claw.min_ram_mb >= 1024 ? `${(claw.min_ram_mb / 1024).toFixed(0)} GB` : `${claw.min_ram_mb} MB`}</span>
        </p>
        {claw.license && (
          <p className="network-detail">
            <span className="network-label">license</span>
            <span>{claw.license}</span>
          </p>
        )}
        {typeof claw.stars === "number" && claw.stars > 0 && (
          <p className="network-detail">
            <span className="network-label">stars</span>
            <span>{"\u2605"} {claw.stars.toLocaleString()}</span>
          </p>
        )}
        {claw.source && (
          <p className="network-detail">
            <span className="network-label">source</span>
            <a
              href={claw.source}
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: "inherit", textDecoration: "underline" }}
            >
              {claw.source.replace(/^https?:\/\//, "").replace(/\.git$/, "")}
            </a>
          </p>
        )}
        {claw.installed_at && (
          <p className="network-detail">
            <span className="network-label">installed</span>
            <span>{new Date(claw.installed_at).toLocaleDateString()}</span>
          </p>
        )}
        {availableSlowWarning && (
          <p className="network-detail" style={{ color: "#f59e0b" }}>
            first install builds from plan — may take ~10 min
          </p>
        )}
        {claw.error && (
          <p className="network-detail" style={{ color: "#ef4444" }}>
            {claw.error}
          </p>
        )}
      </div>

      <div style={{ marginTop: "auto", paddingTop: "8px" }}>
        {(claw.status === "not_installed" || claw.status === "failed") && canInstallFromUI(claw) && (
          <button
            type="button"
            className="network-expose-btn"
            onClick={() => onInstall(claw.name)}
            disabled={busy}
          >
            {claw.status === "failed" ? "retry install" : "install"}
          </button>
        )}
        {claw.status === "ready" && (
          <button
            type="button"
            className="network-expose-btn"
            data-variant="destructive"
            onClick={() => onUninstall(claw.name)}
            disabled={busy}
          >
            uninstall
          </button>
        )}
        {isTransitional && (
          <button type="button" className="network-expose-btn" data-variant="progress" disabled>
            {claw.status === "installing" ? "installing..." : "uninstalling..."}
          </button>
        )}
        {!canInstallFromUI(claw) && claw.status === "not_installed" && (
          <p className="network-detail muted">
            {tier === "detected" ? "pending verification" : tier === "catalog" ? "listing only" : "not available yet"}
          </p>
        )}
      </div>
    </div>
  );
}

export function ClawStorePage() {
  const [claws, setClaws] = useState<ClawCatalogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [activeTier, setActiveTier] = useState<ClawTier>("supported");

  const loadClaws = async () => {
    try {
      setError(null);
      const items = await api.listClaws();
      setClaws(items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load claws");
    } finally {
      setLoading(false);
    }
  };

  const handleInstall = async (name: string) => {
    try {
      setBusy(true);
      setError(null);
      await api.installClaw(name);
      await loadClaws();
    } catch (err) {
      setError(err instanceof Error ? err.message : "install failed");
    } finally {
      setBusy(false);
    }
  };

  const handleUninstall = async (name: string) => {
    try {
      setBusy(true);
      setError(null);
      await api.uninstallClaw(name);
      await loadClaws();
    } catch (err) {
      setError(err instanceof Error ? err.message : "uninstall failed");
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    void loadClaws();
  }, []);

  // Poll every 3s when any claw is in a transitional state.
  const hasTransitional = claws.some(
    (c) => c.status === "installing" || c.status === "uninstalling"
  );

  useEffect(() => {
    if (!hasTransitional) return;
    const interval = setInterval(() => {
      void loadClaws();
    }, 3000);
    return () => clearInterval(interval);
  }, [hasTransitional]);

  // Group claws by tier once per render — O(n) instead of O(n*tiers).
  const byTier = useMemo(() => {
    const groups: Record<ClawTier, ClawCatalogEntry[]> = {
      supported: [],
      available: [],
      detected: [],
      catalog: [],
    };
    for (const c of claws) {
      groups[tierOf(c)].push(c);
    }
    return groups;
  }, [claws]);

  const visible = byTier[activeTier];
  const readyCount = byTier.supported.filter((c) => c.status === "ready").length;

  return (
    <section className="page-section clawstore">
      <header className="page-header">
        <p className="path">~/soyeht/admin/claws</p>
        <h1>claw store</h1>
        <p className="subtitle">
          // install and manage claw types ({readyCount}/{byTier.supported.length} supported installed)
        </p>
        <button
          type="button"
          className="provider-save-btn"
          onClick={() => void loadClaws()}
          disabled={loading}
        >
          {loading ? "..." : "refresh"}
        </button>
      </header>

      {error && <p className="form-error">{error}</p>}
      {loading && claws.length === 0 && <p className="muted">loading catalog...</p>}

      <div role="tablist" aria-label="claw tiers" className="cs-segmented">
        {TIER_TABS.map((t) => {
          const isActive = t === activeTier;
          const count = byTier[t].length;
          return (
            <button
              key={t}
              type="button"
              role="tab"
              aria-selected={isActive}
              onClick={() => setActiveTier(t)}
              className={`cs-segment${isActive ? " cs-segment-active" : ""}`}
              disabled={count === 0 && !isActive}
            >
              <span>{t}</span>
              <span className="cs-count">{count}</span>
            </button>
          );
        })}
      </div>

      <div className="network-grid">
        {visible.length === 0 && !loading && (
          <p className="muted">no claws in the {activeTier} tier yet.</p>
        )}
        {visible.map((claw) => (
          <ClawCard
            key={claw.name}
            claw={claw}
            onInstall={handleInstall}
            onUninstall={handleUninstall}
            busy={busy}
          />
        ))}
      </div>
    </section>
  );
}
