import { QRCodeSVG } from "qrcode.react";
import { useCallback, useEffect, useRef, useState } from "react";

interface QrModalProps {
  token: string;
  expiresAt: string;
  instanceName: string;
  qrHost?: string;
  qrChannel?: string;
  deepLink?: string;
  onClose: () => void;
  onRegenerate: () => void;
}

export function QrModal({ token, expiresAt, instanceName, qrHost, qrChannel, deepLink, onClose, onRegenerate }: QrModalProps) {
  const [secondsLeft, setSecondsLeft] = useState(() => {
    const diff = new Date(expiresAt).getTime() - Date.now();
    return Math.max(0, Math.floor(diff / 1000));
  });

  const expired = secondsLeft <= 0;

  useEffect(() => {
    if (expired) return;
    const timer = setInterval(() => {
      const diff = new Date(expiresAt).getTime() - Date.now();
      const secs = Math.max(0, Math.floor(diff / 1000));
      setSecondsLeft(secs);
      if (secs <= 0) clearInterval(timer);
    }, 1000);
    return () => clearInterval(timer);
  }, [expiresAt, expired]);

  const formatTime = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${String(s).padStart(2, "0")}`;
  };

  // Build the QR content URL — use auto-detected host if available
  const host = qrHost || window.location.host;
  const qrUrl = `theyos://connect?token=${encodeURIComponent(token)}&host=${encodeURIComponent(host)}`;

  const handleBackdropClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (e.target === e.currentTarget) onClose();
    },
    [onClose]
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="qr-modal-backdrop" onClick={handleBackdropClick}>
      <div className="qr-modal">
        <div className="qr-modal-header">
          <strong>connect: {instanceName}</strong>
          <button type="button" onClick={onClose} className="qr-modal-close">
            x
          </button>
        </div>

        <div className="qr-modal-body">
          {expired ? (
            <div className="qr-expired">
              <p>token expired</p>
              <button type="button" onClick={onRegenerate}>
                regenerate
              </button>
            </div>
          ) : (
            <>
              <div className="qr-code-wrapper">
                <QRCodeSVG value={qrUrl} size={200} level="M" />
              </div>
              <p className="qr-timer">
                expires in <strong>{formatTime(secondsLeft)}</strong>
              </p>
              <p className="qr-hint">scan with theyOS mobile app</p>
              {(deepLink || qrUrl) && <CopyableCode value={deepLink || qrUrl} />}
              {qrChannel && (
                <p className="qr-channel">
                  via <strong>{qrChannel}</strong>
                </p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function CopyableCode({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

  const handleCopy = () => {
    navigator.clipboard.writeText(value);
    setCopied(true);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="qr-copyable-code" onClick={handleCopy} title="Click to copy">
      <code>{value}</code>
      <span className="qr-copy-label">{copied ? "copied!" : "click to copy"}</span>
    </div>
  );
}
