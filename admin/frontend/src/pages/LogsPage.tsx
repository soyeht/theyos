import { useState } from "react";
import { api } from "../lib/api";
import { extractErrorMessage } from "../lib/errors";
import { usePolling } from "../lib/hooks";
import type { LogEntry } from "../lib/types";

export function LogsPage() {
  const [items, setItems] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      const data = await api.listLogs(250);
      setItems(data);
      setError(null);
    } catch (err) {
      setError(extractErrorMessage(err, "failed to load logs"));
    } finally {
      setLoading(false);
    }
  };

  usePolling(() => void load(), 4000);

  return (
    <section className="page-section">
      <header className="page-header">
        <p className="path">~/soyeht/admin/logs</p>
        <h1>logs</h1>
        <p className="subtitle">// audit trail and operational events</p>
      </header>

      {error && <p className="form-error">{error}</p>}

      <div className="logs-shell">
        <div className="logs-head">
          <strong>event-stream</strong>
          <span>{loading ? "loading..." : `${items.length} entries`}</span>
        </div>

        <ul className="logs-list">
          {items.map((item) => (
            <li key={item.id}>
              <span className={`level level-${item.level}`}>{item.level}</span>
              <span>{new Date(item.at).toLocaleTimeString()}</span>
              <span>{item.component}</span>
              <span>{item.message}</span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
