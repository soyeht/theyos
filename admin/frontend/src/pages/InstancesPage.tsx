import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { QrModal } from "../components/QrModal";
import { extractErrorMessage } from "../lib/errors";
import { usePolling } from "../lib/hooks";
import { getStatusClass, getStatusIcon } from "../lib/statusUtils";
import type { Instance } from "../lib/types";

export function InstancesPage() {
  const [items, setItems] = useState<Instance[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  // Tracks which action is running per instance: id → action name
  const [pendingAction, setPendingAction] = useState<Record<string, string>>({});

  // Delete confirmation: instance id awaiting confirmation
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  // QR modal state
  const [qrData, setQrData] = useState<{
    token: string;
    expiresAt: string;
    instanceId: string;
    instanceName: string;
    qrHost?: string;
    qrChannel?: string;
    deepLink?: string;
  } | null>(null);

  const load = async () => {
    try {
      setError(null);
      const data = await api.listInstances();
      setItems(data);
    } catch (err) {
      setError(extractErrorMessage(err, "failed to load instances"));
    } finally {
      setLoading(false);
    }
  };

  usePolling(() => void load(), 10000);

  const totals = useMemo(() => {
    const totalTokens = items.reduce((acc, item) => acc + item.tokens_24h, 0);
    const totalMemory = items.reduce((acc, item) => acc + item.memory_mb, 0);
    const avgCPU = items.length === 0 ? 0 : items.reduce((acc, item) => acc + item.cpu_pct, 0) / items.length;
    return { totalTokens, totalMemory, avgCPU };
  }, [items]);

  const runAction = async (id: string, action: "stop" | "restart" | "rebuild" | "delete") => {
    setActionError(null);
    setPendingAction((prev) => ({ ...prev, [id]: action }));
    try {
      if (action === "stop") await api.stopInstance(id);
      else if (action === "restart") await api.restartInstance(id);
      else if (action === "rebuild") await api.rebuildInstance(id);
      else if (action === "delete") await api.deleteInstance(id);
      await load();
    } catch (err) {
      setActionError(extractErrorMessage(err, `failed to ${action} instance`));
    } finally {
      setPendingAction((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
    }
  };

  const handleShowQr = async (id: string, name: string) => {
    try {
      const data = await api.generateQrToken(id);
      setQrData({
        token: data.token,
        expiresAt: data.expires_at,
        instanceId: id,
        instanceName: name,
        qrHost: data.qr_host,
        qrChannel: data.qr_channel,
        deepLink: data.deep_link,
      });
    } catch (err) {
      setError(extractErrorMessage(err, "failed to generate QR code"));
    }
  };

  const handleRegenerateQr = async () => {
    if (!qrData) return;
    await handleShowQr(qrData.instanceId, qrData.instanceName);
  };

  return (
    <section className="page-section">
      <header className="page-header">
        <p className="path">~/soyeht/admin/instances</p>
        <h1>instances</h1>
        <p className="subtitle">// monitoring, state and operational control</p>
      </header>

      <div className="metrics-grid">
        <article>
          <p>tokens-24h</p>
          <h3>{totals.totalTokens}</h3>
        </article>
        <article>
          <p>memory-total</p>
          <h3>{totals.totalMemory}mb</h3>
        </article>
        <article>
          <p>cpu-avg</p>
          <h3>{totals.avgCPU.toFixed(1)}%</h3>
        </article>
        <article>
          <p>instances</p>
          <h3>{items.length}</h3>
        </article>
      </div>

      {(actionError || error) && <p className="form-error">{actionError || error}</p>}

      <div className="table-shell">
        <div className="table-header-row">
          <strong>active-instances</strong>
          <span>$ list --all</span>
        </div>

        <table className="instances-table">
          <thead>
            <tr>
              <th>container_id</th>
              <th>status</th>
              <th>type</th>
              <th>uptime_h</th>
              <th>actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={5}>loading...</td>
              </tr>
            ) : null}

            {!loading && items.length === 0 ? (
              <tr>
                <td colSpan={5}>no instances found</td>
              </tr>
            ) : null}

            {items.map((item) => (
              <tr key={item.id}>
                <td>
                  <div className="instance-id-col">
                    <Link to={`/instances/${encodeURIComponent(item.id)}`}>
                      <strong>{item.name}</strong>
                    </Link>
                    <span>{item.container}</span>
                    {item.provisioning_message && (
                      <span className="provision-msg">{item.provisioning_message}</span>
                    )}
                    {item.provisioning_error && (
                      <span className="provision-error">{item.provisioning_error}</span>
                    )}
                  </div>
                </td>
                <td>
                  <span className={getStatusClass(item.status)}>
                    {getStatusIcon(item.status)} [{item.status}]
                    {item.status === "provisioning" && <span className="spinner-inline" />}
                  </span>
                </td>
                <td>{item.claw_type}</td>
                <td>{item.uptime_hours}</td>
                <td>
                  <div className="actions-inline">
                    <button
                      type="button"
                      onClick={() => void runAction(item.id, "rebuild")}
                      disabled={item.status === "provisioning" || item.id in pendingAction}
                      title="Rebuild with fresh rootfs from snapshot"
                    >
                      {pendingAction[item.id] === "rebuild" ? "rebuilding…" : "rebuild"}
                    </button>
                    <button
                      type="button"
                      onClick={() => void runAction(item.id, "stop")}
                      disabled={item.status === "provisioning" || item.id in pendingAction}
                    >
                      {pendingAction[item.id] === "stop" ? "stopping…" : "stop"}
                    </button>
                    <button
                      type="button"
                      onClick={() => void runAction(item.id, "restart")}
                      disabled={item.status === "provisioning" || item.id in pendingAction}
                    >
                      {pendingAction[item.id] === "restart" ? "restarting…" : "restart"}
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleShowQr(item.id, item.name)}
                      disabled={item.status !== "active"}
                      title="Generate QR code for mobile app"
                    >
                      qr
                    </button>
                    {confirmDelete === item.id ? (
                      <span className="confirm-delete">
                        delete?{" "}
                        <button
                          type="button"
                          onClick={() => {
                            setConfirmDelete(null);
                            void runAction(item.id, "delete");
                          }}
                        >
                          yes
                        </button>
                        <button type="button" onClick={() => setConfirmDelete(null)}>
                          no
                        </button>
                      </span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => setConfirmDelete(item.id)}
                        disabled={item.status === "provisioning" || item.id in pendingAction}
                      >
                        {pendingAction[item.id] === "delete" ? "deleting…" : "delete"}
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {qrData && (
        <QrModal
          token={qrData.token}
          expiresAt={qrData.expiresAt}
          instanceName={qrData.instanceName}
          qrHost={qrData.qrHost}
          qrChannel={qrData.qrChannel}
          deepLink={qrData.deepLink}
          onClose={() => setQrData(null)}
          onRegenerate={() => void handleRegenerateQr()}
        />
      )}
    </section>
  );
}
