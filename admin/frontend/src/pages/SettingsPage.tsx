import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { api } from "../lib/api";
import { extractErrorMessage } from "../lib/errors";
import type { CloudflareStatus, CloudflareZone } from "../lib/types";

/**
 * Settings → Cloudflare.
 *
 * One-screen automation of the operator workflow that used to require:
 *   1. Cloudflare dashboard click-fest to make a tunnel,
 *   2. SSH into the host to drop a token file,
 *   3. nix edit + `sudo soyeht update`,
 *   4. dashboard click-fest again to add a CNAME.
 *
 * The form here just asks for an API token (scopes: Tunnel:Edit + DNS:Edit),
 * resolves zones via the API, and on Enable does steps 1–3 server-side. From
 * then on, every Add Public Site also automates step 4.
 */
export function SettingsPage() {
  const [status, setStatus] = useState<CloudflareStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);

  // Setup form state (only meaningful when status?.configured === false)
  const [apiToken, setApiToken] = useState("");
  const [zones, setZones] = useState<CloudflareZone[] | null>(null);
  const [selectedZoneId, setSelectedZoneId] = useState<string>("");
  const [tunnelName, setTunnelName] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [enabling, setEnabling] = useState(false);
  const [setupError, setSetupError] = useState<string | null>(null);

  // Disconnect state (only meaningful when status?.configured === true)
  const [disconnecting, setDisconnecting] = useState(false);
  const [disconnectError, setDisconnectError] = useState<string | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const s = await api.cloudflareStatus();
      setStatus(s);
      setStatusError(null);
    } catch (err) {
      setStatusError(extractErrorMessage(err, "failed to load Cloudflare status"));
    }
  }, []);

  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  const handleVerify = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      setSetupError(null);
      const token = apiToken.trim();
      if (!token) {
        setSetupError("paste an API token first");
        return;
      }
      setVerifying(true);
      try {
        const { zones: result } = await api.cloudflareListZones(token);
        if (result.length === 0) {
          setSetupError("token is valid, but it can't manage any zones — add a Zone:DNS:Edit policy");
          setZones([]);
          return;
        }
        setZones(result);
        // Auto-select the first zone for the common one-zone case.
        setSelectedZoneId(result[0].id);
        // Sensible default tunnel name; operator can edit before clicking Enable.
        if (!tunnelName) setTunnelName("theyos-tunnel");
      } catch (err) {
        setSetupError(extractErrorMessage(err, "failed to list zones"));
      } finally {
        setVerifying(false);
      }
    },
    [apiToken, tunnelName],
  );

  const handleEnable = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      setSetupError(null);
      const zone = zones?.find((z) => z.id === selectedZoneId);
      if (!zone) {
        setSetupError("pick a zone first");
        return;
      }
      const name = tunnelName.trim();
      if (!name) {
        setSetupError("tunnel name is required");
        return;
      }
      setEnabling(true);
      try {
        await api.cloudflareSetup(apiToken.trim(), zone.account_id, zone.id, name);
        // Reset form state, reload status — UI flips to Connected card.
        setApiToken("");
        setZones(null);
        setSelectedZoneId("");
        setTunnelName("");
        await loadStatus();
      } catch (err) {
        setSetupError(extractErrorMessage(err, "Enable failed"));
      } finally {
        setEnabling(false);
      }
    },
    [apiToken, zones, selectedZoneId, tunnelName, loadStatus],
  );

  const handleDisconnect = useCallback(async () => {
    if (
      !window.confirm(
        "Disconnect Cloudflare?\n\nThis will:\n  • delete every public-site CNAME from your Cloudflare zone\n  • delete the tunnel\n  • stop cloudflared on this host\n\nExisting public sites will keep their DB rows but their public URLs will stop resolving.",
      )
    ) {
      return;
    }
    setDisconnectError(null);
    setDisconnecting(true);
    try {
      await api.cloudflareDisconnect();
      await loadStatus();
    } catch (err) {
      setDisconnectError(extractErrorMessage(err, "disconnect failed"));
    } finally {
      setDisconnecting(false);
    }
  }, [loadStatus]);

  return (
    <section className="page-section">
      <header className="page-header">
        <p className="path">~/soyeht/admin/settings/cloudflare</p>
        <h1>cloudflare tunnel</h1>
        <p className="subtitle">
          // operator-facing setup — paste an API token, pick a zone, click Enable
        </p>
      </header>

      {statusError && <p className="form-error">{statusError}</p>}

      {!status && !statusError && <p>loading…</p>}

      {status && !status.configured && (
        <ConfigureForm
          apiToken={apiToken}
          setApiToken={setApiToken}
          zones={zones}
          selectedZoneId={selectedZoneId}
          setSelectedZoneId={setSelectedZoneId}
          tunnelName={tunnelName}
          setTunnelName={setTunnelName}
          verifying={verifying}
          enabling={enabling}
          setupError={setupError}
          handleVerify={handleVerify}
          handleEnable={handleEnable}
        />
      )}

      {status && status.configured && (
        <ConnectedCard
          status={status}
          disconnecting={disconnecting}
          disconnectError={disconnectError}
          handleDisconnect={handleDisconnect}
        />
      )}
    </section>
  );
}

// ── Sub-components ──────────────────────────────────────────────────────────

type ConfigureFormProps = {
  apiToken: string;
  setApiToken: (v: string) => void;
  zones: CloudflareZone[] | null;
  selectedZoneId: string;
  setSelectedZoneId: (v: string) => void;
  tunnelName: string;
  setTunnelName: (v: string) => void;
  verifying: boolean;
  enabling: boolean;
  setupError: string | null;
  handleVerify: (e: FormEvent) => void;
  handleEnable: (e: FormEvent) => void;
};

function ConfigureForm(props: ConfigureFormProps) {
  return (
    <>
      <p>
        Public sites use a Cloudflare Tunnel to publish to the internet without
        exposing this host's IP. Configure once, then every Add Public Site is a
        one-click operation.
      </p>

      <form
        className="create-form"
        onSubmit={props.zones ? props.handleEnable : props.handleVerify}
      >
        <h3>cloudflare api token</h3>
        <label>
          <input
            type="password"
            placeholder="cfat_…"
            value={props.apiToken}
            onChange={(e) => props.setApiToken(e.target.value)}
            disabled={props.verifying || props.enabling || props.zones != null}
            required
          />
        </label>
        <details>
          <summary>how to create a token?</summary>
          <ol style={{ marginTop: "0.5rem", paddingLeft: "1.5rem" }}>
            <li>
              Sign in to{" "}
              <a
                href="https://dash.cloudflare.com/profile/api-tokens"
                target="_blank"
                rel="noopener noreferrer"
              >
                Cloudflare → My Profile → API Tokens
              </a>
            </li>
            <li>Click "Create Token" → "Custom token"</li>
            <li>
              Permissions:
              <ul>
                <li>Account — Cloudflare Tunnel — Edit</li>
                <li>Zone — DNS — Edit (limit to the zone you'll publish under)</li>
              </ul>
            </li>
            <li>Account / Zone resources: scope to your account + the relevant zone</li>
            <li>Create Token, copy the value, paste it above</li>
          </ol>
        </details>

        {!props.zones && (
          <button type="submit" disabled={props.verifying}>
            {props.verifying ? "verifying…" : "verify & list zones"}
          </button>
        )}

        {props.zones && props.zones.length > 0 && (
          <>
            <label>
              zone
              <select
                value={props.selectedZoneId}
                onChange={(e) => props.setSelectedZoneId(e.target.value)}
                disabled={props.enabling}
              >
                {props.zones.map((z) => (
                  <option key={z.id} value={z.id}>
                    {z.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              tunnel name
              <input
                type="text"
                placeholder="theyos-tunnel"
                value={props.tunnelName}
                onChange={(e) => props.setTunnelName(e.target.value)}
                disabled={props.enabling}
                required
              />
            </label>
            <button type="submit" disabled={props.enabling}>
              {props.enabling ? "enabling…" : "enable"}
            </button>
          </>
        )}

        {props.setupError && <p className="form-error">{props.setupError}</p>}
      </form>
    </>
  );
}

type ConnectedCardProps = {
  status: Extract<CloudflareStatus, { configured: true }>;
  disconnecting: boolean;
  disconnectError: string | null;
  handleDisconnect: () => void;
};

function ConnectedCard({ status, disconnecting, disconnectError, handleDisconnect }: ConnectedCardProps) {
  return (
    <div className="public-sites-section">
      <p>
        <strong>✓ configured</strong>
      </p>
      <table style={{ marginTop: "0.5rem" }}>
        <tbody>
          <tr>
            <th>account</th>
            <td>
              <code>{status.account_id}</code>
            </td>
          </tr>
          <tr>
            <th>zone</th>
            <td>
              <code>{status.zone_name}</code>
            </td>
          </tr>
          <tr>
            <th>tunnel</th>
            <td>
              <code>{status.tunnel_name}</code>
            </td>
          </tr>
          <tr>
            <th>cloudflared</th>
            <td>
              {status.cloudflared_running ? (
                <span className="status-running">● running</span>
              ) : (
                <span className="status-stopped">● not running</span>
              )}
            </td>
          </tr>
          <tr>
            <th>configured at</th>
            <td>{status.configured_at}</td>
          </tr>
        </tbody>
      </table>

      <p style={{ marginTop: "1rem" }}>
        Add public sites under <code>{status.zone_name}</code> from any Instance
        page — the CNAME and tunnel ingress are wired automatically.
      </p>

      <button
        type="button"
        onClick={handleDisconnect}
        disabled={disconnecting}
        style={{ marginTop: "1rem" }}
      >
        {disconnecting ? "disconnecting…" : "disconnect cloudflare"}
      </button>
      {disconnectError && <p className="form-error">{disconnectError}</p>}
    </div>
  );
}
