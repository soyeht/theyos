import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { CaddyStatus, ChannelStatus, NetworkStatus } from "../lib/types";

function channelIcon(ch: ChannelStatus): string {
  if (ch.detected) return "\u25cf"; // ● filled circle
  if (ch.configured) return "\u25cb"; // ○ empty circle
  return "\u2013"; // – dash
}

function channelColor(ch: ChannelStatus): string {
  if (ch.detected) return "#22c55e";  // green-500, always visible in both themes
  if (ch.configured) return "#f59e0b";  // amber-500, configured but not running
  return "var(--text-muted)";
}

function caddySummary(caddy: CaddyStatus): string {
  if (caddy.running) return `running (${caddy.admin_url})`;
  if (caddy.status_detail) return caddy.status_detail;
  if (caddy.installed) return "installed but admin API is not responding";
  return "not installed";
}

function ChannelCard({ channel, onExpose }: { channel: ChannelStatus; onExpose?: (channel: string, enabled: boolean) => void }) {
  return (
    <div className="network-card">
      <div className="network-card-header">
        <span
          className="network-status-dot"
          style={{ color: channelColor(channel) }}
        >
          {channelIcon(channel)}
        </span>
        <strong>{channel.type}</strong>
      </div>

      <div className="network-card-body">
        {channel.ip && (
          <p className="network-detail">
            <span className="network-label">ip</span>
            <code>{channel.ip}</code>
          </p>
        )}
        {channel.hostname && (
          <p className="network-detail">
            <span className="network-label">host</span>
            <code>{channel.hostname}</code>
          </p>
        )}
        {channel.has_dns !== undefined && (
          <p className="network-detail">
            <span className="network-label">dns</span>
            <span>{channel.has_dns ? "\u2713" : "\u2717"}</span>
          </p>
        )}
        {channel.has_https !== undefined && (
          <p className="network-detail">
            <span className="network-label">https</span>
            <span>{channel.has_https ? "\u2713" : "\u2717"}</span>
          </p>
        )}

        {!channel.detected && channel.status_detail && (
          <p className="network-detail muted">{channel.status_detail}</p>
        )}
        {!channel.detected && !channel.status_detail && !channel.configured && (
          <p className="network-detail muted">not configured</p>
        )}
        {!channel.detected && !channel.status_detail && channel.configured && (
          <p className="network-detail muted">configured but not detected</p>
        )}
      </div>

      {channel.urls.length > 0 && (
        <div className="network-card-urls">
          {channel.urls.map((url) => (
            <a
              key={url}
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              className="network-url"
            >
              {url}
            </a>
          ))}
        </div>
      )}

      {channel.type === "tailscale" && channel.detected && onExpose && (
        <button
          type="button"
          className="network-expose-btn"
          onClick={() => onExpose("tailscale", true)}
        >
          expose panel via HTTPS
        </button>
      )}
    </div>
  );
}

export function NetworkPage() {
  const [status, setStatus] = useState<NetworkStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exposing, setExposing] = useState(false);

  const handleExpose = async (channel: string, enabled: boolean) => {
    try {
      setExposing(true);
      setError(null);
      const resp = await fetch("/api/v1/network/expose", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ channel, enabled }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setError(data.error || "Failed to expose");
        return;
      }
      if (data.url) {
        alert(`Panel exposed at ${data.url}`);
      }
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to expose");
    } finally {
      setExposing(false);
    }
  };

  const loadStatus = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getNetworkStatus();
      setStatus(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load network status");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadStatus();
    // Refresh every 30 seconds
    const interval = setInterval(() => {
      void loadStatus();
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <section className="page-section networkpage">
      <header className="page-header">
        <p className="path">~/soyeht/admin/network</p>
        <h1>network</h1>
        <p className="subtitle">// access channels and connectivity</p>
        <button
          type="button"
          className="btn-outline-sm"
          onClick={() => void loadStatus()}
          disabled={loading}
        >
          {loading ? "..." : "refresh"}
        </button>
      </header>

      {error && <p className="form-error">{error}</p>}
      {loading && !status && <p className="muted">detecting channels...</p>}

      {status && (
        <>
          <div className="network-grid">
            {status.channels.map((ch) => (
              <ChannelCard key={ch.type} channel={ch} onExpose={exposing ? undefined : handleExpose} />
            ))}
          </div>

          <div className="network-caddy">
            <span className="network-label">caddy</span>
            <span>{caddySummary(status.caddy)}</span>
          </div>

          {!status.caddy.running && status.caddy.status_detail && (
            <p className="network-caddy-hint">
              {status.caddy.status_detail}
            </p>
          )}
        </>
      )}
    </section>
  );
}
