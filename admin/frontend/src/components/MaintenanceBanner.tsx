import { useState, useCallback } from "react";
import { api } from "../lib/api";
import { usePolling } from "../lib/hooks";
import type { MaintenanceStatus } from "../lib/types";

const POLL_INTERVAL_MS = 15_000;

export function MaintenanceBanner() {
  const [status, setStatus] = useState<MaintenanceStatus | null>(null);

  const poll = useCallback(() => {
    api.getMaintenanceStatus().then(setStatus).catch(() => {
      // Silently ignore errors (network down, not logged in, etc.)
      setStatus(null);
    });
  }, []);

  usePolling(poll, POLL_INTERVAL_MS);

  if (!status?.maintenance) {
    return null;
  }

  return (
    <div className="maintenance-banner" role="alert">
      <span className="maintenance-banner-icon">&#9888;</span>
      <span className="maintenance-banner-text">
        maintenance mode: {status.reason || status.state}
      </span>
      {status.retry_after_secs > 0 && (
        <span className="maintenance-banner-retry">
          (retry in ~{status.retry_after_secs}s)
        </span>
      )}
    </div>
  );
}
