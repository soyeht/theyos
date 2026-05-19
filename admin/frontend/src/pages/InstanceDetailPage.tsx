import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError, api } from "../lib/api";
import { extractErrorMessage } from "../lib/errors";
import { usePolling } from "../lib/hooks";
import { getStatusClass, getStatusIcon } from "../lib/statusUtils";
import type {
  CloudflaredWarning,
  Instance,
  LlmActiveResponse,
  LlmCatalog,
  PublicSite,
  PublicSiteInstructions,
} from "../lib/types";

export function InstanceDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [instance, setInstance] = useState<Instance | null>(null);
  const [instanceError, setInstanceError] = useState<string | null>(null);

  const loadInstance = useCallback(async () => {
    if (!id) return;
    try {
      const inst = await api.getInstance(id);
      setInstance(inst);
      setInstanceError(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        navigate("/instances", { replace: true });
        return;
      }
      setInstanceError(extractErrorMessage(err, "failed to load instance"));
    }
  }, [id, navigate]);

  usePolling(() => void loadInstance(), 10000);

  if (!id) {
    return <Navigate to="/instances" />;
  }

  return (
    <section className="page-section">
      <header className="page-header">
        <p className="path">~/soyeht/admin/instances/{id}</p>
        <h1>{instance ? instance.name : id}</h1>
        <p className="subtitle">
          // per-instance configuration
          {instance ? (
            <>
              {" "}— <span className={getStatusClass(instance.status)}>
                {getStatusIcon(instance.status)} [{instance.status}]
              </span>
            </>
          ) : null}
        </p>
        <p>
          <Link to="/instances">← back to instances</Link>
        </p>
      </header>

      {instanceError && <p className="form-error">{instanceError}</p>}

      <PublicSitesSection instance={instance} />
      <LlmOverrideSection instance={instance} />
    </section>
  );
}

/// Per-claw LLM override picker. Lets the operator pin a specific
/// provider+model for this claw_type while everything else uses the
/// global default. Backed by PUT /api/v1/llm/active/{claw_type} (set) and
/// DELETE /api/v1/llm/active/{claw_type} (clear).
///
/// The picker only acts on `claw_type`, not the instance id — the proxy
/// routes by claw type (one override applies to every instance of that
/// type). Document this in the help text so operators don't expect
/// per-instance granularity.
function LlmOverrideSection({ instance }: { instance: Instance | null }) {
  const clawType = instance?.claw_type;
  const [catalog, setCatalog] = useState<LlmCatalog | null>(null);
  const [active, setActive] = useState<LlmActiveResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedProvider, setSelectedProvider] = useState("");
  const [selectedModel, setSelectedModel] = useState("");

  const reload = useCallback(async () => {
    if (!clawType) return;
    try {
      const [c, a] = await Promise.all([api.llmCatalog(), api.llmActive()]);
      setCatalog(c);
      setActive(a);
      const ov = a.per_claw[clawType];
      if (ov) {
        setSelectedProvider(ov.provider);
        setSelectedModel(ov.model);
      } else {
        setSelectedProvider("");
        setSelectedModel("");
      }
      setError(null);
    } catch (e) {
      setError(extractErrorMessage(e, "failed to load llm config"));
    }
  }, [clawType]);

  useEffect(() => {
    void reload();
  }, [reload]);

  if (!instance || !clawType) {
    return null;
  }

  const currentOverride = active?.per_claw[clawType];
  const providerEntry = catalog?.entries.find((e) => e.id === selectedProvider);

  const handleSave = async () => {
    if (!selectedProvider || !selectedModel) return;
    setBusy(true);
    try {
      await api.llmSetActiveForClaw(clawType, {
        provider: selectedProvider,
        model: selectedModel,
      });
      await reload();
    } catch (e) {
      setError(extractErrorMessage(e, "failed to set override"));
    } finally {
      setBusy(false);
    }
  };

  const handleClear = async () => {
    setBusy(true);
    try {
      await api.llmClearActiveForClaw(clawType);
      await reload();
    } catch (e) {
      setError(extractErrorMessage(e, "failed to clear override"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="section">
      <header>
        <h2>llm engine</h2>
        <p className="muted">
          override the default provider+model for every claw of type{" "}
          <code>{clawType}</code>. clear it to inherit the global default.
        </p>
      </header>
      {error && <p className="form-error">{error}</p>}
      {active && (
        <p>
          current:{" "}
          {currentOverride ? (
            <>
              <strong>{currentOverride.provider}</strong> · {currentOverride.model}{" "}
              <em>(override)</em>
            </>
          ) : (
            <>
              <strong>{active.default.provider}</strong> · {active.default.model}{" "}
              <em>(default)</em>
            </>
          )}
        </p>
      )}
      <div className="form-row">
        <label>
          <span>provider</span>
          <select
            value={selectedProvider}
            onChange={(e) => {
              setSelectedProvider(e.target.value);
              setSelectedModel("");
            }}
            disabled={busy || !catalog}
          >
            <option value="">— pick —</option>
            {catalog?.entries.map((entry) => (
              <option key={entry.id} value={entry.id}>
                {entry.display_name}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>model</span>
          <select
            value={selectedModel}
            onChange={(e) => setSelectedModel(e.target.value)}
            disabled={busy || !providerEntry}
          >
            <option value="">— pick —</option>
            {providerEntry?.models.map((m) => (
              <option key={m.id} value={m.id}>
                {m.display_name}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="form-actions">
        <button
          type="button"
          className="btn-primary"
          disabled={busy || !selectedProvider || !selectedModel}
          onClick={() => void handleSave()}
        >
          {busy ? "saving…" : currentOverride ? "update override" : "set override"}
        </button>
        {currentOverride && (
          <button
            type="button"
            disabled={busy}
            onClick={() => void handleClear()}
          >
            clear override
          </button>
        )}
      </div>
    </section>
  );
}

function Navigate({ to }: { to: string }) {
  const navigate = useNavigate();
  useEffect(() => {
    navigate(to, { replace: true });
  }, [navigate, to]);
  return null;
}

type PublicSitesState = {
  sites: PublicSite[];
  instructions: PublicSiteInstructions | null;
  warning: CloudflaredWarning | null;
};

function PublicSitesSection({ instance }: { instance: Instance | null }) {
  const id = instance?.id;
  const [state, setState] = useState<PublicSitesState>({
    sites: [],
    instructions: null,
    warning: null,
  });
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [domain, setDomain] = useState("");
  const [guestPort, setGuestPort] = useState("3000");
  const [submitting, setSubmitting] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!id) return;
    try {
      const resp = await api.listPublicSites(id);
      setState({
        sites: resp.sites,
        instructions: resp.instructions,
        warning: resp.cloudflared_warning ?? null,
      });
      setListError(null);
    } catch (err) {
      setListError(extractErrorMessage(err, "failed to load public sites"));
    } finally {
      setLoading(false);
    }
  }, [id]);

  usePolling(() => void load(), 10000);

  const handleAdd = async (event: FormEvent) => {
    event.preventDefault();
    if (!id) return;
    const trimmed = domain.trim();
    if (!trimmed) return;
    const port = Number(guestPort);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      setActionError("guest_port must be an integer between 1 and 65535");
      return;
    }
    setSubmitting(true);
    setActionError(null);
    try {
      const resp = await api.addPublicSite(id, trimmed, port);
      setState({
        sites: resp.sites,
        instructions: resp.instructions,
        warning: resp.cloudflared_warning ?? null,
      });
      setDomain("");
    } catch (err) {
      setActionError(extractErrorMessage(err, "failed to add public site"));
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (siteDomain: string) => {
    if (!id) return;
    setPendingDelete(siteDomain);
    setActionError(null);
    try {
      await api.deletePublicSite(id, siteDomain);
      await load();
    } catch (err) {
      setActionError(
        extractErrorMessage(err, `failed to delete ${siteDomain}`)
      );
    } finally {
      setPendingDelete(null);
    }
  };

  const isActive = instance?.status === "active";

  return (
    <div className="public-sites-section">
      <div className="table-shell">
        <div className="table-header-row">
          <strong>public-sites</strong>
          <span>$ list --instance {id ?? ""}</span>
        </div>

        {!isActive && instance && (
          <p className="public-sites-disabled">
            instance is <strong>{instance.status}</strong> — activate it to
            manage public sites
          </p>
        )}

        {state.warning && (
          <div className="public-sites-warning">
            <strong>cloudflared:</strong> {state.warning.message}
            <ul>
              {state.warning.missing.map((d) => (
                <li key={d}>{d}</li>
              ))}
            </ul>
            <p className="muted">
              checked: <code>{state.warning.config_path}</code>
            </p>
          </div>
        )}

        {(listError || actionError) && (
          <p className="form-error">{actionError || listError}</p>
        )}

        <table className="instances-table">
          <thead>
            <tr>
              <th>domain</th>
              <th>guest_port</th>
              <th>target</th>
              <th>actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={4}>loading...</td>
              </tr>
            )}
            {!loading && state.sites.length === 0 && (
              <tr>
                <td colSpan={4}>no public sites configured</td>
              </tr>
            )}
            {state.sites.map((site) => (
              <tr key={site.domain}>
                <td>
                  <strong>{site.domain}</strong>
                  {!site.enabled && <span className="muted"> [disabled]</span>}
                </td>
                <td>{site.guest_port}</td>
                <td>
                  <span className="muted">
                    {site.target_host}:{site.target_port}
                  </span>
                </td>
                <td>
                  <button
                    type="button"
                    onClick={() => void handleDelete(site.domain)}
                    disabled={pendingDelete === site.domain}
                  >
                    {pendingDelete === site.domain ? "removing…" : "remove"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {isActive && (
        <form className="create-form" onSubmit={(e) => void handleAdd(e)}>
          <h3>add public site</h3>
          <label>
            domain
            <input
              type="text"
              placeholder="livre.org"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              required
              disabled={submitting}
            />
          </label>
          <details className="public-sites-advanced">
            <summary>advanced</summary>
            <label>
              guest_port
              <input
                type="number"
                min={1}
                max={65535}
                value={guestPort}
                onChange={(e) => setGuestPort(e.target.value)}
                disabled={submitting}
              />
            </label>
            <p className="muted">
              port your service listens on inside the VM. default 3000 covers
              Node, Next.js dev, and most frameworks. only change if your
              service uses a different port.
            </p>
          </details>
          <button type="submit" disabled={submitting}>
            {submitting ? "adding…" : "add"}
          </button>
        </form>
      )}

      {state.instructions && (
        <details className="public-sites-instructions">
          <summary>setup instructions</summary>
          <ol style={{ marginTop: "0.5rem", paddingLeft: "1.5rem" }}>
            <li>
              {state.instructions.step1}{" "}
              <Link to={state.instructions.settings_link ?? "/settings"}>
                go to Settings →
              </Link>
            </li>
            <li>{state.instructions.step2}</li>
            <li>{state.instructions.step3}</li>
          </ol>
          <p className="muted">
            default guest_port: {state.instructions.default_guest_port}
          </p>
        </details>
      )}
    </div>
  );
}
