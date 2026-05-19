// Live /models page — talks to /api/v1/llm/* through server-rs.
//
// The visual design twin lives at /models-preview (ModelsPage.tsx), which
// stays mock-only so designers can iterate without booting server-rs. This
// page intentionally has a thinner UI surface: it focuses on the operator
// workflow (configure provider → set active → see it work) rather than
// model-shopping UX. The mock preview owns the marketing surface.

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../lib/api";
import type {
  LlmActiveProfile,
  LlmActiveResponse,
  LlmCatalog,
  LlmCatalogEntry,
  LlmProvidersResponse,
  LlmProviderSummary,
  LlmTestResponse,
} from "../lib/types";

type ConnectFormState = {
  entry: LlmCatalogEntry;
  apiKey: string;
  selectedBaseUrl: "default" | "coding-plan";
  busy: boolean;
  error: string | null;
  testResult: LlmTestResponse | null;
};

export function ModelsLivePage() {
  const [catalog, setCatalog] = useState<LlmCatalog | null>(null);
  const [active, setActive] = useState<LlmActiveResponse | null>(null);
  const [providers, setProviders] = useState<LlmProvidersResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [connectForm, setConnectForm] = useState<ConnectFormState | null>(null);
  const [activatingProvider, setActivatingProvider] = useState<string | null>(null);
  const [removingProvider, setRemovingProvider] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      const [c, a, p] = await Promise.all([
        api.llmCatalog(),
        api.llmActive(),
        api.llmListProviders(),
      ]);
      setCatalog(c);
      setActive(a);
      setProviders(p);
      setError(null);
    } catch (e) {
      const msg = e instanceof ApiError ? `${e.status}: ${e.message}` : String(e);
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  // Index providers by id for quick lookups when rendering catalog cards.
  const providersById = useMemo(() => {
    const map: Record<string, LlmProviderSummary> = {};
    for (const p of providers?.providers ?? []) {
      map[p.id] = p;
    }
    return map;
  }, [providers]);

  const handleConnect = (entry: LlmCatalogEntry) => {
    setConnectForm({
      entry,
      apiKey: "",
      selectedBaseUrl: "default",
      busy: false,
      error: null,
      testResult: null,
    });
  };

  const submitConnect = async () => {
    if (!connectForm) return;
    setConnectForm({ ...connectForm, busy: true, error: null, testResult: null });
    const { entry, apiKey, selectedBaseUrl } = connectForm;
    try {
      const baseUrl =
        selectedBaseUrl === "coding-plan" && entry.coding_plan_base_url
          ? entry.coding_plan_base_url
          : entry.default_base_url;
      const credentialAccount =
        entry.credential.kind === "api-key" ? `llm.api_key.${entry.id}` : undefined;
      await api.llmUpsertProvider({
        id: entry.id,
        kind: entry.kind,
        base_url: baseUrl,
        credential_account: credentialAccount,
        models: entry.models.map((m) => m.id),
        cli_flavor: entry.cli_flavor,
        credential: apiKey || undefined,
      });
      // Live probe immediately so the operator sees the connection
      // worked (or sees a typed error message before they ship a claw
      // that uses this provider).
      const test = await api.llmTestProvider(entry.id);
      setConnectForm({
        ...connectForm,
        busy: false,
        error: null,
        testResult: test,
      });
      await reload();
    } catch (e) {
      const msg = e instanceof ApiError ? `${e.status}: ${e.message}` : String(e);
      setConnectForm({ ...connectForm, busy: false, error: msg, testResult: null });
    }
  };

  const handleSetActive = async (entry: LlmCatalogEntry, modelId: string) => {
    setActivatingProvider(entry.id);
    try {
      const next: LlmActiveProfile = { provider: entry.id, model: modelId };
      await api.llmSetActive(next);
      await reload();
    } catch (e) {
      const msg = e instanceof ApiError ? `${e.status}: ${e.message}` : String(e);
      setError(msg);
    } finally {
      setActivatingProvider(null);
    }
  };

  const handleRemove = async (entryId: string) => {
    if (!confirm(`Remove provider ${entryId}? Its credential will also be deleted from the host keystore.`))
      return;
    setRemovingProvider(entryId);
    try {
      await api.llmDeleteProvider(entryId);
      await reload();
    } catch (e) {
      const msg = e instanceof ApiError ? `${e.status}: ${e.message}` : String(e);
      setError(msg);
    } finally {
      setRemovingProvider(null);
    }
  };

  if (loading) {
    return (
      <div className="models-live">
        <h1>models</h1>
        <p>loading…</p>
      </div>
    );
  }

  if (error && !catalog) {
    return (
      <div className="models-live">
        <h1>models</h1>
        <p className="error">{error}</p>
        <p>
          Is <code>theyos-llm-proxy</code> running on the host? Check{" "}
          <code>systemctl status theyos-llm-proxy</code>.
        </p>
      </div>
    );
  }

  const cat = catalog!;
  const act = active!;

  return (
    <div className="models-live">
      <h1>models</h1>
      <p className="path">~/soyeht/admin/models</p>

      {error && <p className="error">{error}</p>}

      <section className="active-banner">
        <h2>active</h2>
        <p>
          default: <strong>{act.default.provider}</strong> ·{" "}
          <strong>{act.default.model}</strong>
        </p>
        {Object.entries(act.per_claw).length > 0 && (
          <details>
            <summary>per-claw overrides ({Object.keys(act.per_claw).length})</summary>
            <ul>
              {Object.entries(act.per_claw).map(([claw, p]) => (
                <li key={claw}>
                  <code>{claw}</code> → <strong>{p.provider}</strong> · {p.model}{" "}
                  <button
                    type="button"
                    onClick={async () => {
                      await api.llmClearActiveForClaw(claw);
                      await reload();
                    }}
                  >
                    clear
                  </button>
                </li>
              ))}
            </ul>
          </details>
        )}
      </section>

      <section className="providers-grid">
        <h2>providers</h2>
        {cat.entries.map((entry) => {
          const configured = providersById[entry.id];
          const isDefault =
            act.default.provider === entry.id;
          return (
            <article
              key={entry.id}
              className={`provider-card${configured ? " configured" : ""}${
                isDefault ? " active" : ""
              }`}
            >
              <header>
                <h3>{entry.display_name}</h3>
                <span className={`kind-badge kind-${entry.kind}`}>{entry.kind}</span>
              </header>
              <p>{entry.tagline}</p>

              {entry.credential.kind === "cli-oauth" && (
                <p className="hint">
                  install <code>{entry.credential.cli_binary}</code> on the host
                  and run its login command
                </p>
              )}

              {configured ? (
                <div className="configured-state">
                  <p>
                    configured
                    {configured.has_credential ? " · credential stored" : " · no credential"}
                  </p>
                  <div className="model-list">
                    {entry.models.map((m) => (
                      <button
                        key={m.id}
                        type="button"
                        className={
                          isDefault && act.default.model === m.id
                            ? "model-btn active"
                            : "model-btn"
                        }
                        disabled={activatingProvider === entry.id}
                        onClick={() => void handleSetActive(entry, m.id)}
                      >
                        {m.display_name}
                      </button>
                    ))}
                  </div>
                  <button
                    type="button"
                    className="remove-btn"
                    disabled={removingProvider === entry.id || configured.in_use}
                    onClick={() => void handleRemove(entry.id)}
                    title={
                      configured.in_use
                        ? "switch the active provider before removing this one"
                        : "remove provider + delete credential"
                    }
                  >
                    {removingProvider === entry.id ? "removing…" : "remove"}
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  className="connect-btn"
                  onClick={() => handleConnect(entry)}
                >
                  {entry.credential.kind === "api-key" ? "add api key" : "configure"}
                </button>
              )}
            </article>
          );
        })}
      </section>

      {connectForm && (
        <div
          className="modal-backdrop"
          onClick={() => setConnectForm(null)}
        >
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h2>connect {connectForm.entry.display_name}</h2>
            {connectForm.entry.credential.kind === "api-key" && (
              <>
                <label>
                  <span>
                    api key
                    {" "}<small>({connectForm.entry.credential.env_hint})</small>
                  </span>
                  <input
                    type="password"
                    value={connectForm.apiKey}
                    onChange={(e) =>
                      setConnectForm({ ...connectForm, apiKey: e.target.value })
                    }
                    autoFocus
                  />
                </label>
                {connectForm.entry.coding_plan_base_url && (
                  <label>
                    <span>endpoint</span>
                    <select
                      value={connectForm.selectedBaseUrl}
                      onChange={(e) =>
                        setConnectForm({
                          ...connectForm,
                          selectedBaseUrl: e.target.value as "default" | "coding-plan",
                        })
                      }
                    >
                      <option value="default">standard api</option>
                      <option value="coding-plan">coding plan</option>
                    </select>
                  </label>
                )}
              </>
            )}
            {connectForm.entry.credential.kind === "cli-oauth" && (
              <p className="hint">
                no api key needed — this provider uses your local{" "}
                <code>{connectForm.entry.credential.cli_binary}</code> login. Click
                save to register the provider with the proxy.
              </p>
            )}
            {connectForm.error && (
              <p className="error">{connectForm.error}</p>
            )}
            {connectForm.testResult && (
              <p className={connectForm.testResult.ok ? "ok" : "error"}>
                {connectForm.testResult.ok
                  ? `live probe ok · ${connectForm.testResult.latency_ms} ms`
                  : `probe failed: ${connectForm.testResult.error}`}
              </p>
            )}
            <div className="modal-actions">
              <button type="button" onClick={() => setConnectForm(null)}>
                cancel
              </button>
              <button
                type="button"
                className="primary"
                disabled={connectForm.busy}
                onClick={() => void submitConnect()}
              >
                {connectForm.busy ? "saving…" : "save"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
