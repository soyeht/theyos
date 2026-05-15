import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { Terminal } from "xterm";
import { FitAddon } from "xterm-addon-fit";
import "xterm/css/xterm.css";
import { api, ApiError } from "../lib/api";
import type { Workspace } from "../lib/types";

const MIN_FONT = 10;
const MAX_FONT = 18;

/** Initial delay (ms) between reconnect attempts. */
const RECONNECT_BASE_DELAY = 1000;
/** Maximum delay (ms) between reconnect attempts. */
const RECONNECT_MAX_DELAY = 10000;


function sendResize(ws: WebSocket, term: Terminal) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
  }
}

/** Compute exponential backoff delay with jitter, capped at RECONNECT_MAX_DELAY. */
function reconnectDelay(attempt: number): number {
  const base = Math.min(RECONNECT_BASE_DELAY * 2 ** attempt, RECONNECT_MAX_DELAY);
  // Add ±25% jitter to avoid thundering herd
  const jitter = base * 0.25 * (Math.random() * 2 - 1);
  return Math.round(base + jitter);
}

// v2 WS protocol: Binary frames starting with this prefix are control markers;
// the rest of the frame is the marker name in ASCII. Any other Binary frame is
// raw PTY output. See admin/rust/server-rs/src/handlers_terminal.rs.
const CTL_PREFIX = new Uint8Array([0x00, 0x01, 0x43, 0x54, 0x4c, 0x3a]); // "\x00\x01CTL:"

function startsWithCtlPrefix(bytes: Uint8Array): boolean {
  if (bytes.length < CTL_PREFIX.length) return false;
  for (let i = 0; i < CTL_PREFIX.length; i++) {
    if (bytes[i] !== CTL_PREFIX[i]) return false;
  }
  return true;
}

function handleCtlMarker(name: string, term: Terminal) {
  switch (name) {
    case "replay_start":
      term.options.disableStdin = true;
      break;
    case "replay_done":
      // Re-enable stdin AFTER xterm drains prior writes.
      term.write("", () => {
        term.options.disableStdin = false;
      });
      break;
    case "subscriber_lagged":
      console.warn("[terminals/ws] subscriber lagged; some output may be missing");
      break;
    case "session_ended":
    case "log_full":
      // onclose handles reconnect/mirror flow; just log here.
      console.info("[terminals/ws] ctl", name);
      break;
    default:
      console.warn("[terminals/ws] unknown ctl marker", name);
  }
}

/** Tmux shortcut map: browser key → tmux key (sent after prefix \x02). */
const TMUX_SHORTCUTS: Record<string, string> = {
  "\\": "%",           // split vertical
  "-": '"',            // split horizontal
  "k": "x",            // close pane
  "z": "z",            // zoom toggle
  "s": "s",            // session list (tmux)
  "h": "[",            // scroll/copy mode
  "x": "d",            // detach
  " ": " ",            // cycle layouts (Space)
};

/** Arrow key → ANSI escape sequence (for tmux pane navigation). */
const ARROW_ESCAPES: Record<string, string> = {
  ArrowUp: "\x1b[A",
  ArrowDown: "\x1b[B",
  ArrowLeft: "\x1b[D",
  ArrowRight: "\x1b[C",
};

// ── Session Picker ──────────────────────────────────────────────────────────

/** Format a relative time string like "5 min ago" or "2 days ago". */
function relativeTime(dateStr: string | null): string {
  if (!dateStr) return "never";
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffMs = now - then;
  if (Number.isNaN(diffMs)) return "unknown";
  const mins = Math.floor(diffMs / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

interface SessionPickerProps {
  workspaces: Workspace[];
  warning: string | null;
  onSelect: (ws: Workspace) => void;
  onCreate: (displayName: string) => void;
  onRename: (id: string, displayName: string) => void;
  onDelete: (id: string) => void;
}

function SessionPicker({ workspaces, warning, onSelect, onCreate, onRename, onDelete }: SessionPickerProps) {
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const handleCreate = () => {
    if (creating) {
      onCreate(newName.trim());
      setNewName("");
      setCreating(false);
    } else {
      setCreating(true);
    }
  };

  const handleRenameStart = (ws: Workspace) => {
    setRenamingId(ws.id);
    setRenameValue(ws.display_name);
  };

  const handleRenameConfirm = () => {
    if (renamingId) {
      onRename(renamingId, renameValue.trim());
      setRenamingId(null);
    }
  };

  const handleDeleteClick = (ws: Workspace) => {
    setConfirmDeleteId(ws.id);
  };

  const handleDeleteConfirm = () => {
    if (confirmDeleteId) {
      onDelete(confirmDeleteId);
      setConfirmDeleteId(null);
    }
  };

  const confirmWs = confirmDeleteId ? workspaces.find((w) => w.id === confirmDeleteId) : null;

  return (
    <div className="session-picker" data-testid="session-picker">
      <div className="session-picker-header">
        <span>// sessions</span>
      </div>
      <div className="session-picker-list">
        {workspaces.map((ws) => (
          <div
            key={ws.id}
            className={`session-picker-item ${ws.status === "inactive" ? "inactive" : ""}`}
            data-testid={`session-item-${ws.id}`}
          >
            <span className="session-status-dot">{ws.status === "active" ? "●" : "○"}</span>
            {renamingId === ws.id ? (
              <input
                className="session-rename-input"
                type="text"
                value={renameValue}
                onChange={(e) => setRenameValue(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleRenameConfirm();
                  if (e.key === "Escape") setRenamingId(null);
                }}
                autoFocus
                data-testid="session-rename-input"
              />
            ) : (
              <button
                type="button"
                className="session-name-btn"
                onClick={() => onSelect(ws)}
                title={`Connect to ${ws.display_name || ws.id}`}
              >
                <span className="session-display-name">{ws.display_name || `session ${ws.id.slice(0, 8)}`}</span>
                <span className="session-last-activity">{relativeTime(ws.last_attach_at)}</span>
              </button>
            )}
            <span className="session-actions">
              <button type="button" className="session-action-btn" title="Rename" onClick={() => handleRenameStart(ws)} data-testid={`rename-${ws.id}`}>✎</button>
              <button type="button" className="session-action-btn" title="Delete" onClick={() => handleDeleteClick(ws)} data-testid={`delete-${ws.id}`}>×</button>
            </span>
          </div>
        ))}
      </div>

      {confirmDeleteId && confirmWs && (
        <div className="session-confirm-delete" data-testid="confirm-delete">
          <p>
            {confirmWs.is_connected
              ? `session '${confirmWs.display_name || confirmWs.id.slice(0, 8)}' is active. deleting will end all running processes. continue?`
              : `delete session '${confirmWs.display_name || confirmWs.id.slice(0, 8)}'?`}
          </p>
          <button type="button" onClick={handleDeleteConfirm} data-testid="confirm-delete-yes">
            {confirmWs.is_connected ? "delete anyway" : "delete"}
          </button>
          <button type="button" onClick={() => setConfirmDeleteId(null)} data-testid="confirm-delete-no">cancel</button>
        </div>
      )}

      {creating ? (
        <div className="session-create-form">
          <input
            type="text"
            placeholder="session name..."
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleCreate();
              if (e.key === "Escape") { setCreating(false); setNewName(""); }
            }}
            autoFocus
            data-testid="new-session-name-input"
          />
          <button type="button" onClick={handleCreate} data-testid="create-session-confirm">create</button>
          <button type="button" onClick={() => { setCreating(false); setNewName(""); }}>cancel</button>
        </div>
      ) : (
        <button type="button" className="session-create-btn" onClick={handleCreate} data-testid="new-session-btn">
          + new session
        </button>
      )}

      {warning && (
        <div className="session-picker-warning" data-testid="session-warning">{warning}</div>
      )}
    </div>
  );
}

interface TerminalPanelProps {
  container: string;
  sessionId: string;
  fontSize: number;
  isReconnecting: boolean;
  isActive: boolean;
  onActivate: () => void;
  panelIndex: number;
  containers: string[];
  onContainerChange: (value: string) => void;
  onFontChange: (delta: number) => void;
  onReconnect: () => void;
  reconnectKey: number;
  workspaceError: boolean;
  onRetryWorkspace: () => void;
  onShowPicker?: () => void;
  currentSessionName?: string;
  onNewSession: (displayName: string) => void;
  onNextSession: () => void;
  onPrevSession: () => void;
  onLastSession: () => void;
  onRenameSession: (newName: string) => void;
}

function TerminalPanel({
  container,
  sessionId,
  fontSize,
  isReconnecting,
  isActive,
  onActivate,
  panelIndex,
  containers,
  onContainerChange,
  onFontChange,
  onReconnect,
  reconnectKey,
  workspaceError,
  onRetryWorkspace,
  onShowPicker,
  currentSessionName,
  onNewSession,
  onNextSession,
  onPrevSession,
  onLastSession,
  onRenameSession,
}: TerminalPanelProps) {
  const divRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttempt = useRef(0);
  /** Set to true when the cleanup function runs (component unmount or deps change). */
  const disposed = useRef(false);
  /** Set to true when the user explicitly triggers a reconnect. */
  const intentionalClose = useRef(false);
  /** Set to true when the session is in mirror mode (another device is commander).
   *  Prevents visibility/online handlers from auto-reconnecting and kicking the
   *  real commander off. Reset to false when the user explicitly takes command. */
  const isMirrorRef = useRef(false);
  const isActiveRef = useRef(isActive);
  const [connStatus, setConnStatus] = useState<"connected" | "disconnected" | "reconnecting" | "mirror">("disconnected");
  const [inlinePrompt, setInlinePrompt] = useState<{ mode: "new" | "rename"; value: string } | null>(null);

  const onNewSessionRef = useRef(onNewSession);
  const onNextSessionRef = useRef(onNextSession);
  const onPrevSessionRef = useRef(onPrevSession);
  const onLastSessionRef = useRef(onLastSession);
  const onRenameSessionRef = useRef(onRenameSession);
  const setInlinePromptRef = useRef(setInlinePrompt);
  const currentSessionNameRef = useRef(currentSessionName);

  useEffect(() => { isActiveRef.current = isActive; }, [isActive]);

  useEffect(() => {
    onNewSessionRef.current = onNewSession;
    onNextSessionRef.current = onNextSession;
    onPrevSessionRef.current = onPrevSession;
    onLastSessionRef.current = onLastSession;
    onRenameSessionRef.current = onRenameSession;
    setInlinePromptRef.current = setInlinePrompt;
    currentSessionNameRef.current = currentSessionName;
  });

  const sendTmuxKey = useCallback((key: string) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "input", data: `\x02${key}` }));
    }
  }, []);

  const logWs = useCallback((event: string, details: Record<string, unknown> = {}) => {
    console.info("[terminals/ws]", event, {
      container,
      activeSession: currentSessionNameRef.current,
      ...details,
    });
  }, [container]);

  const clearReconnectTimer = useCallback((reason: string) => {
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current);
      reconnectTimer.current = null;
      logWs("reconnect-timer-cleared", { reason });
    }
  }, [logWs]);

  const connectWs = useCallback(
    (term: Terminal, fitAddon: FitAddon, sid: string) => {
      if (disposed.current || !container) return;
      clearReconnectTimer("connect-start");
      isMirrorRef.current = false;

      // Suppress stdin while replaying the snapshot buffer — prevents xterm.js
      // from echoing DA1/DA2 query responses as typed input on reconnect.
      term.options.disableStdin = true;

      const proto = location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(
        `${proto}://${location.host}/api/v1/terminals/${encodeURIComponent(container)}/pty?session=${sid}&cols=${term.cols}&rows=${term.rows}&client=web`
      );
      ws.binaryType = "arraybuffer";
      wsRef.current = ws;
      logWs("connect", { sid, cols: term.cols, rows: term.rows });

      ws.onopen = () => {
        clearReconnectTimer("socket-open");
        reconnectAttempt.current = 0;
        setConnStatus("connected");
        logWs("open", { sid, cols: term.cols, rows: term.rows });
        fitAddon.fit();
        sendResize(ws, term);
        if (isActiveRef.current) term.focus();
      };

      ws.onmessage = (e) => {
        if (disposed.current) return;

        if (e.data instanceof ArrayBuffer) {
          const bytes = new Uint8Array(e.data);
          if (startsWithCtlPrefix(bytes)) {
            const marker = new TextDecoder().decode(bytes.subarray(CTL_PREFIX.length));
            handleCtlMarker(marker, term);
            return;
          }
          // Raw PTY bytes — xterm accepts Uint8Array directly.
          term.write(bytes);
          return;
        }

        // Legacy safety net: if a Text frame ever slips through, write it.
        if (typeof e.data === "string") {
          term.write(e.data);
        }
      };

      ws.onerror = () => {
        // onerror is always followed by onclose — handle reconnect there.
      };

      ws.onclose = (event) => {
        if (disposed.current || intentionalClose.current) return;
        logWs("close", {
          sid,
          code: event.code,
          reason: event.reason,
          wasMirror: isMirrorRef.current,
          readyState: ws.readyState,
        });

        // Code 4000 = another device took command. Show placeholder.
        // Mark isMirrorRef so visibility/online handlers don't auto-reconnect.
        if (event.code === 4000) {
          clearReconnectTimer("mirror-close");
          isMirrorRef.current = true;
          setConnStatus("mirror");
          return;
        }

        const attempt = reconnectAttempt.current;
        // Show "reconnecting" for the first ~5 min, then "disconnected"
        // to update the UI indicator — but keep reconnecting either way.
        setConnStatus(attempt < 30 ? "reconnecting" : "disconnected");

        // On first failure and every 10th attempt, check if auth is still valid.
        if (attempt === 0 || attempt % 10 === 0) {
          api.me().catch((err: unknown) => {
            // Only redirect on 401 (session expired). Other errors (500, network)
            // should not kick the user to login.
            if (err instanceof ApiError && err.status === 401) {
              term.write("\r\n\x1b[31m[session expired — redirecting to sign in...]\x1b[0m\r\n");
              setTimeout(() => { window.location.href = "/login"; }, 2000);
            }
          });
        }

        const delay = reconnectDelay(attempt);
        const delaySec = (delay / 1000).toFixed(1);
        term.write(`\r\n\x1b[33m[disconnected — reconnecting in ${delaySec}s...]\x1b[0m\r\n`);
        reconnectAttempt.current = attempt + 1;
        logWs("schedule-reconnect", { sid, attempt: reconnectAttempt.current, delayMs: delay });

        reconnectTimer.current = setTimeout(() => {
          reconnectTimer.current = null;
          if (disposed.current) return;
          // Reuse the same session ID so fc-ssh reconnects to the existing
          // tmux session inside the VM (tmux new-session -A).  The shell
          // state, running processes, and scrollback survive the disconnect.
          logWs("fire-reconnect", { sid, attempt: reconnectAttempt.current });
          connectWs(term, fitAddon, sid);
        }, delay);
      };
    },
    [clearReconnectTimer, container, logWs],
  );

  useEffect(() => {
    if (!divRef.current || !container || !sessionId) return;

    disposed.current = false;
    intentionalClose.current = false;
    reconnectAttempt.current = 0;

    const term = new Terminal({
      fontSize,
      fontFamily: '"JetBrains Mono", "Comic Sans MS", cursive',
      cursorBlink: true,
      scrollback: 2000,
      theme: { background: "#0d0f10", foreground: "#cfe9d7", cursor: "#ffffff" },
      customGlyphs: true,   // pixel-perfect block/box drawing chars (default, explicit)
      lineHeight: 1.0,      // tight cell packing for correct QR code aspect ratio
      letterSpacing: 0,     // no extra spacing that distorts block alignment
    });
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(divRef.current);
    // Hide the xterm.js scrollbar visually — scroll via mouse/trackpad still works.
    const vp = divRef.current.querySelector(".xterm-viewport") as HTMLElement | null;
    if (vp) vp.style.overflow = "hidden";
    fitAddon.fit();

    // xterm measures cell width at open(); if JetBrains Mono wasn't loaded
    // yet it measured the fallback. Re-run measurement once the font is ready.
    if (document.fonts?.ready) {
      document.fonts.ready.then(() => {
        if (disposed.current) return;
        // Re-assigning fontFamily forces xterm to recompute char metrics.
        term.options.fontFamily = term.options.fontFamily;
        fitAddon.fit();
        if (wsRef.current) sendResize(wsRef.current, term);
      });
    }

    // ── OSC 52 clipboard: tmux sends selected text here ──────────────
    // When tmux has `set-clipboard on` and the user selects text with the
    // mouse, tmux encodes the selection as base64 in an OSC 52 sequence.
    // We decode it and write to the browser clipboard.
    const hostDiv = divRef.current;
    term.parser.registerOscHandler(52, (data: string) => {
      const idx = data.indexOf(";");
      if (idx === -1) return true;
      const payload = data.slice(idx + 1);
      if (!payload || payload === "?") return true;
      try {
        const text = atob(payload);
        navigator.clipboard.writeText(text).catch(() => {});
        // Brief "// copied" flash so the user knows it worked
        if (hostDiv) {
          const tag = document.createElement("div");
          tag.textContent = "// copied";
          tag.className = "copy-toast";
          hostDiv.appendChild(tag);
          requestAnimationFrame(() => { tag.style.opacity = "1"; });
          setTimeout(() => {
            tag.style.opacity = "0";
            setTimeout(() => tag.remove(), 300);
          }, 1000);
        }
      } catch {
        // invalid base64 — ignore
      }
      return true;
    });

    const handleFocusIn = () => {
      if (!isActiveRef.current) onActivate();
    };
    divRef.current.addEventListener("focusin", handleFocusIn);

    termRef.current = term;
    fitRef.current = fitAddon;

    // Wire terminal input → active WebSocket (registered once; reads wsRef).
    term.onData((data) => {
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "input", data }));
      }
    });

    // Clipboard: Ctrl+C copies selection (or passes SIGINT), Ctrl+V pastes.
    term.attachCustomKeyEventHandler((ev) => {
      if (ev.type !== "keydown") return true;

      // Ctrl+C: copy selection if any, otherwise let SIGINT through
      if (ev.ctrlKey && !ev.shiftKey && !ev.altKey && ev.key === "c") {
        if (term.hasSelection()) {
          navigator.clipboard.writeText(term.getSelection());
          term.clearSelection();
          return false; // prevent SIGINT
        }
        return true; // no selection → normal SIGINT
      }

      // Ctrl+V: paste from clipboard
      if (ev.ctrlKey && !ev.shiftKey && !ev.altKey && ev.key === "v") {
        navigator.clipboard.readText().then((text) => {
          if (text) term.paste(text);
        });
        return false; // prevent default browser paste
      }

      // Ctrl++/Ctrl+=: increase font size (prevent browser zoom)
      if (ev.ctrlKey && !ev.shiftKey && !ev.altKey && (ev.key === "=" || ev.key === "+")) {
        onFontChange(1);
        return false;
      }

      // Ctrl+-: decrease font size (prevent browser zoom)
      if (ev.ctrlKey && !ev.shiftKey && !ev.altKey && ev.key === "-") {
        onFontChange(-1);
        return false;
      }

      // Cmd+Shift (Mac) or Ctrl+Shift (Linux): tmux shortcuts
      const isCmdShift = (ev.metaKey || ev.ctrlKey) && ev.shiftKey && !ev.altKey;
      if (isCmdShift) {
        // Arrow keys → navigate panes
        if (ev.key.startsWith("Arrow")) {
          const arrow = ARROW_ESCAPES[ev.key];
          if (arrow) { sendTmuxKey(arrow); return false; }
        }
        // Session shortcuts (app-level, not tmux)
        const lk = ev.key.toLowerCase();
        if (lk === "t") { setInlinePromptRef.current({ mode: "new", value: "" }); return false; }
        if (lk === "]") { onNextSessionRef.current(); return false; }
        if (lk === "[") { onPrevSessionRef.current(); return false; }
        if (lk === "l") { onLastSessionRef.current(); return false; }
        if (lk === "r") { setInlinePromptRef.current({ mode: "rename", value: currentSessionNameRef.current ?? "" }); return false; }
        // All other shortcuts via lookup table
        const tmuxKey = TMUX_SHORTCUTS[lk];
        if (tmuxKey !== undefined) { sendTmuxKey(tmuxKey); return false; }
      }

      return true; // all other keys pass through
    });

    // Check if another device already has command before connecting.
    // If so, show mirror placeholder instead of creating a PTY.
    api.sessionInfo(container, sessionId).then((info) => {
      if (disposed.current) return;
      logWs("session-info", { sessionId, commander: info.commander });
      if (info.commander) {
        isMirrorRef.current = true;
        setConnStatus("mirror");
      } else {
        connectWs(term, fitAddon, sessionId);
      }
    }).catch(() => {
      // On error (old server, network), connect anyway
      logWs("session-info-error", { sessionId });
      if (!disposed.current) connectWs(term, fitAddon, sessionId);
    });

    const onResize = () => {
      fitAddon.fit();
      if (wsRef.current) sendResize(wsRef.current, term);
    };
    window.addEventListener("resize", onResize);

    // ── Visibility / online handlers (reconnect on wake / network restore) ──
    // Close old socket before opening a new one to prevent two concurrent
    // WebSocket connections racing (output corruption, double input).
    const killOldSocket = () => {
      const old = wsRef.current;
      if (old) { old.onclose = null; old.onerror = null; old.close(); }
      wsRef.current = null;
    };
    const onVisibilityChange = () => {
      // Don't auto-reconnect when in mirror mode — another device is commander.
      if (isMirrorRef.current) return;
      if (document.visibilityState === "visible" && !disposed.current) {
        const ws = wsRef.current;
        if (!ws || ws.readyState !== WebSocket.OPEN) {
          killOldSocket();
          reconnectAttempt.current = 0;
          clearReconnectTimer("visibility-change");
          connectWs(term, fitAddon, sessionId);
        }
      }
    };
    const onOnline = () => {
      // Don't auto-reconnect when in mirror mode — another device is commander.
      if (isMirrorRef.current) return;
      if (!disposed.current) {
        const ws = wsRef.current;
        if (!ws || ws.readyState !== WebSocket.OPEN) {
          killOldSocket();
          reconnectAttempt.current = 0;
          clearReconnectTimer("online");
          connectWs(term, fitAddon, sessionId);
        }
      }
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("online", onOnline);

    return () => {
      disposed.current = true;
      intentionalClose.current = true;
      window.removeEventListener("resize", onResize);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.removeEventListener("online", onOnline);
      divRef.current?.removeEventListener("focusin", handleFocusIn);
      clearReconnectTimer("cleanup");
      // Null out handlers BEFORE closing to prevent the old onclose from
      // firing after the next effect has already reset disposed/intentionalClose.
      // Without this, the stale onclose sees disposed=false and reconnects to
      // the OLD container, overwriting wsRef and stealing input.
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.onerror = null;
        wsRef.current.close();
      }
      wsRef.current = null;
      if (termRef.current) {
        termRef.current.options.disableStdin = false;
      }
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [container, sessionId, reconnectKey, connectWs, clearReconnectTimer, logWs]);

  // Apply font size changes without remounting
  useEffect(() => {
    if (termRef.current) {
      termRef.current.options.fontSize = fontSize;
      fitRef.current?.fit();
      if (wsRef.current) sendResize(wsRef.current, termRef.current);
    }
  }, [fontSize]);

  // Focus terminal when panel becomes active
  useEffect(() => {
    if (isActive && termRef.current) {
      const raf = requestAnimationFrame(() => termRef.current?.focus());
      return () => cancelAnimationFrame(raf);
    }
  }, [isActive]);

  // Expose terminal I/O on window for Chrome MCP automation
  useEffect(() => {
    if (!isActive) return;

    const w = window as any;

    w.__terminalInput = (data: string) => {
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "input", data }));
        return true;
      }
      return false;
    };

    w.__terminalBuffer = (lines = 50) => {
      const term = termRef.current;
      if (!term) return "";
      const buf = term.buffer.active;
      const start = Math.max(0, buf.cursorY + buf.baseY - lines + 1);
      const result: string[] = [];
      for (let i = start; i <= buf.cursorY + buf.baseY; i++) {
        const line = buf.getLine(i);
        if (line) result.push(line.translateToString(true));
      }
      return result.join("\n");
    };

    return () => {
      delete w.__terminalInput;
      delete w.__terminalBuffer;
    };
  }, [isActive]);

  return (
    <article
      className={`terminal-card ${isActive ? "active" : ""}`}
      onClick={onActivate}
    >
      <p className="terminal-label">
        container-{panelIndex + 1}
        {container && (
          <span
            className={`conn-status conn-${connStatus}`}
            title={connStatus}
          >
            {connStatus === "connected" ? " //" : connStatus === "reconnecting" ? " ..." : connStatus === "mirror" ? " ◉" : " !!"}
          </span>
        )}
      </p>

      <div className="terminal-toolbar">
        <span className="toolbar-group">
          <select
            value={container}
            onChange={(e) => onContainerChange(e.target.value)}
            onClick={(e) => e.stopPropagation()}
          >
            <option value="">select...</option>
            {containers.map((c) => (
              <option value={c} key={`${panelIndex}-${c}`}>
                {c}
              </option>
            ))}
          </select>

          <button
            className="toolbar-reconnect"
            disabled={isReconnecting}
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onReconnect();
            }}
          >
            {isReconnecting ? "reconnecting..." : "reconnect"}
          </button>
        </span>

        <span className="toolbar-group">
          <button
            className="toolbar-icon"
            type="button"
            title="Decrease font size"
            onClick={(e) => {
              e.stopPropagation();
              onFontChange(-1);
            }}
          >
            A-
          </button>
          <button
            className="toolbar-icon"
            type="button"
            title="Increase font size"
            onClick={(e) => {
              e.stopPropagation();
              onFontChange(1);
            }}
          >
            A+
          </button>
        </span>

        <span className="toolbar-group">
          <button
            className="toolbar-icon"
            type="button"
            title="Split vertical (Cmd+Shift+\\)"
            onClick={(e) => {
              e.stopPropagation();
              sendTmuxKey("%");
            }}
          >
            ⎸
          </button>
          <button
            className="toolbar-icon"
            type="button"
            title="Split horizontal (Cmd+Shift+-)"
            onClick={(e) => {
              e.stopPropagation();
              sendTmuxKey('"');
            }}
          >
            ─
          </button>
          <button
            className="toolbar-icon"
            type="button"
            title="New session (Ctrl+Shift+T)"
            onClick={(e) => {
              e.stopPropagation();
              setInlinePrompt({ mode: "new", value: "" });
            }}
          >
            +
          </button>
        </span>

        {onShowPicker && (
          <span className="toolbar-group">
            <button
              className="toolbar-workspace-switcher"
              type="button"
              title="Switch workspace"
              onClick={(e) => { e.stopPropagation(); onShowPicker(); }}
            >
              ⇋ {currentSessionName || "sessions"}
            </button>
          </span>
        )}
      </div>

      {inlinePrompt && (
        <div className="session-name-prompt">
          <input
            type="text"
            placeholder={inlinePrompt.mode === "new" ? "session name..." : "rename session..."}
            value={inlinePrompt.value}
            onChange={(e) => setInlinePrompt({ ...inlinePrompt, value: e.target.value })}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                const val = inlinePrompt.value.trim();
                if (inlinePrompt.mode === "new") onNewSession(val);
                else if (val) onRenameSession(val);
                setInlinePrompt(null);
              }
              if (e.key === "Escape") { setInlinePrompt(null); termRef.current?.focus(); }
            }}
            autoFocus
          />
          <button
            type="button"
            onClick={() => {
              const val = inlinePrompt.value.trim();
              if (inlinePrompt.mode === "new") onNewSession(val);
              else if (val) onRenameSession(val);
              setInlinePrompt(null);
            }}
          >
            {inlinePrompt.mode === "new" ? "create" : "rename"}
          </button>
          <button type="button" onClick={() => { setInlinePrompt(null); termRef.current?.focus(); }}>
            cancel
          </button>
        </div>
      )}

      {container && !workspaceError ? (
        sessionId ? (
          <div style={{ position: 'relative', flex: 1, display: 'flex', flexDirection: 'column' }}>
            <div
              ref={divRef}
              className="terminal-view"
              onMouseDown={() => onActivate()}
              onClick={(e) => {
                e.stopPropagation();
                onActivate();
              }}
            />
            {connStatus === "mirror" && (
              <div className="commander-placeholder">
                <p>Session controlled from another device</p>
                <button type="button" onClick={() => {
                  const term = termRef.current;
                  const fit = fitRef.current;
                  if (term && fit && sessionId) {
                    clearReconnectTimer("take-command");
                    logWs("take-command", { sessionId });
                    reconnectAttempt.current = 0;
                    connectWs(term, fit, sessionId);
                  }
                }}>Take Command</button>
              </div>
            )}
          </div>
        ) : (
          <div className="terminal-placeholder">// resolving workspace...</div>
        )
      ) : container && workspaceError ? (
        <div className="terminal-placeholder">
          // workspace unavailable &mdash;{" "}
          <button type="button" onClick={(e) => { e.stopPropagation(); onRetryWorkspace(); }}>
            retry
          </button>
        </div>
      ) : (
        <div className="terminal-placeholder">// select a container to open a terminal</div>
      )}
    </article>
  );
}

export function TerminalsPage() {
  const [searchParams] = useSearchParams();
  const preselectedContainer = searchParams.get("container");

  const [containers, setContainers] = useState<string[]>([]);
  const [panelCount, setPanelCount] = useState(1);
  const [selectedContainers, setSelectedContainers] = useState<string[]>([""]);
  // Session IDs are derived from localStorage (persisted across tab reloads)
  // or generated fresh. They are updated via setPanelSessionIds when the
  // container changes.
  const [panelSessionIds, setPanelSessionIds] = useState<string[]>(() => [""]);
  const [reconnectingPanels, setReconnectingPanels] = useState<boolean[]>([false]);
  const [reconnectKeys, setReconnectKeys] = useState<number[]>([0]);
  const [workspaceErrors, setWorkspaceErrors] = useState<boolean[]>([false]);
  const [fontSizes, setFontSizes] = useState<number[]>([12]);
  const [activePanel, setActivePanel] = useState(0);
  const [panelSessionNames, setPanelSessionNames] = useState<string[]>([""]);
  /** Per-panel workspace lists — non-null means we fetched and got 2+ workspaces (picker mode). */
  const [panelWorkspaces, setPanelWorkspaces] = useState<(Workspace[] | null)[]>([null]);
  /** Per-panel warning strings from listWorkspaces (shown when count > 8). */
  const [panelWarnings, setPanelWarnings] = useState<(string | null)[]>([null]);
  /** Tracks which panel indexes have had their workspace resolved. Keyed by index
   *  (not container name) so two panels with the same container resolve independently. */
  const resolvedRef = useRef<Set<number>>(new Set());

  useEffect(() => {
    const load = async () => {
      const items = await api.listContainers();

      // If preselected container from URL isn't in the list yet (e.g. freshly
      // created instance), include it so the dropdown and WebSocket work.
      const allContainers =
        preselectedContainer && !items.includes(preselectedContainer)
          ? [preselectedContainer, ...items]
          : items;
      setContainers(allContainers);

      if (preselectedContainer) {
        setSelectedContainers((prev) => {
          const next = [...prev];
          next[0] = preselectedContainer;
          for (let i = 1; i < panelCount; i += 1) {
            if (!next[i]) {
              const remaining = allContainers.filter(
                (c) => !next.slice(0, i).includes(c) && c !== preselectedContainer
              );
              next[i] = remaining[0] ?? "";
            }
          }
          return next;
        });
      } else {
        setSelectedContainers((prev) => {
          const next = [...prev];
          for (let i = 0; i < panelCount; i += 1) {
            if (!next[i]) {
              next[i] = allContainers[i] ?? "";
            }
          }
          return next;
        });
      }
    };

    void load();
  }, [preselectedContainer, panelCount]);

  useEffect(() => {
    setSelectedContainers((prev) => {
      const next = [...prev];
      while (next.length < panelCount) {
        next.push(containers[next.length] ?? "");
      }
      return next.slice(0, panelCount);
    });

    setFontSizes((prev) => {
      const next = [...prev];
      while (next.length < panelCount) {
        next.push(12);
      }
      return next.slice(0, panelCount);
    });

    setPanelSessionIds((prev) => {
      const next = [...prev];
      while (next.length < panelCount) {
        next.push("");
      }
      return next.slice(0, panelCount);
    });

    setReconnectingPanels((prev) => {
      const next = [...prev];
      while (next.length < panelCount) {
        next.push(false);
      }
      return next.slice(0, panelCount);
    });

    setReconnectKeys((prev) => {
      const next = [...prev];
      while (next.length < panelCount) {
        next.push(0);
      }
      return next.slice(0, panelCount);
    });

    setWorkspaceErrors((prev) => {
      const next = [...prev];
      while (next.length < panelCount) {
        next.push(false);
      }
      return next.slice(0, panelCount);
    });

    setPanelSessionNames((prev) => {
      const next = [...prev];
      while (next.length < panelCount) {
        next.push("");
      }
      return next.slice(0, panelCount);
    });

    setPanelWorkspaces((prev) => {
      const next = [...prev];
      while (next.length < panelCount) {
        next.push(null);
      }
      return next.slice(0, panelCount);
    });

    setPanelWarnings((prev) => {
      const next = [...prev];
      while (next.length < panelCount) {
        next.push(null);
      }
      return next.slice(0, panelCount);
    });
  }, [panelCount, containers]);

  // Derive session IDs from server workspace API when containers change.
  // Tries listWorkspaces first: if 2+ workspaces exist, shows the session
  // picker. Otherwise falls back to getTerminalWorkspace (auto-connect).
  // Retries on failure with error state instead of silent failure.
  useEffect(() => {
    let cancelled = false;
    const resolve = async () => {
      for (let i = 0; i < selectedContainers.length; i++) {
        const c = selectedContainers[i] ?? "";
        if (!c || resolvedRef.current.has(i)) continue;

        // Retry up to 3 times with 1s delay on failure.
        let resolved = false;
        for (let attempt = 0; attempt < 3; attempt++) {
          if (cancelled) return;
          try {
            // Try multi-workspace list first.
            let usePickerMode = false;
            try {
              const resp = await api.listWorkspaces(c);
              if (!cancelled && resp && resp.data && resp.data.length >= 2) {
                // Multiple workspaces — show picker.
                usePickerMode = true;
                resolvedRef.current.add(i);
                setPanelWorkspaces((prev) => {
                  const next = [...prev];
                  next[i] = resp.data;
                  return next;
                });
                setPanelWarnings((prev) => {
                  const next = [...prev];
                  next[i] = resp.warning ?? null;
                  return next;
                });
                setWorkspaceErrors((prev) => {
                  const next = [...prev];
                  next[i] = false;
                  return next;
                });
                resolved = true;
              }
            } catch {
              // listWorkspaces not available or failed — fall through to getTerminalWorkspace.
            }

            if (!usePickerMode && !cancelled) {
              // 0-1 workspaces or listWorkspaces unavailable — auto-connect.
              const ws = await api.getTerminalWorkspace(c);
              if (!cancelled) {
                resolvedRef.current.add(i);
                setPanelSessionIds((prev) => {
                  const next = [...prev];
                  next[i] = ws.session_id;
                  return next;
                });
                setPanelSessionNames((prev) => {
                  const next = [...prev];
                  next[i] = ws.display_name ?? "";
                  return next;
                });
                setPanelWorkspaces((prev) => {
                  const next = [...prev];
                  next[i] = null;
                  return next;
                });
                setWorkspaceErrors((prev) => {
                  const next = [...prev];
                  next[i] = false;
                  return next;
                });
                resolved = true;
              }
            }
            break; // success
          } catch {
            if (attempt < 2) await new Promise((r) => setTimeout(r, 1000));
          }
        }
        // After 3 failures, show error.
        if (!resolved && !cancelled) {
          setWorkspaceErrors((prev) => {
            const next = [...prev];
            next[i] = true;
            return next;
          });
        }
      }
    };
    void resolve();
    return () => { cancelled = true; };
  }, [selectedContainers]);

  const panelIndexes = useMemo(() => Array.from({ length: panelCount }, (_, i) => i), [panelCount]);

  const updatePanelContainer = (index: number, value: string) => {
    // Clear resolved tracking so the new container re-resolves.
    resolvedRef.current.delete(index);
    setSelectedContainers((prev) => {
      const next = [...prev];
      next[index] = value;
      return next;
    });
    // Clear session ID + error + workspace list; the useEffect on
    // selectedContainers will resolve the server-owned workspace
    // session ID asynchronously.
    setPanelSessionIds((prev) => {
      const next = [...prev];
      next[index] = "";
      return next;
    });
    setPanelSessionNames((prev) => {
      const next = [...prev];
      next[index] = "";
      return next;
    });
    setPanelWorkspaces((prev) => {
      const next = [...prev];
      next[index] = null;
      return next;
    });
    setPanelWarnings((prev) => {
      const next = [...prev];
      next[index] = null;
      return next;
    });
    setWorkspaceErrors((prev) => {
      const next = [...prev];
      next[index] = false;
      return next;
    });
  };

  const updateFont = (index: number, delta: number) => {
    setFontSizes((prev) => {
      const next = [...prev];
      next[index] = Math.min(MAX_FONT, Math.max(MIN_FONT, (next[index] ?? 12) + delta));
      return next;
    });
  };

  /** Select a workspace from the picker — sets the session ID and hides the picker. */
  const selectWorkspace = (index: number, workspace: Workspace) => {
    setPanelSessionIds((prev) => {
      const next = [...prev];
      next[index] = workspace.session_id;
      return next;
    });
    setPanelSessionNames((prev) => {
      const next = [...prev];
      next[index] = workspace.display_name ?? "";
      return next;
    });
    // Clear the workspace list to hide the picker.
    setPanelWorkspaces((prev) => {
      const next = [...prev];
      next[index] = null;
      return next;
    });
  };

  /** Create a new workspace and connect to it. */
  const createAndConnect = async (index: number, displayName: string) => {
    const container = selectedContainers[index];
    if (!container) return;
    try {
      const ws = await api.createWorkspace(container, displayName);
      selectWorkspace(index, ws);
    } catch (error) {
      console.error("failed to create workspace", error);
    }
  };

  /** Rename a workspace. */
  const renameWorkspaceHandler = async (index: number, id: string, displayName: string) => {
    const container = selectedContainers[index];
    if (!container) return;
    try {
      await api.renameWorkspace(container, id, displayName);
      // Refresh the workspace list.
      const resp = await api.listWorkspaces(container);
      setPanelWorkspaces((prev) => {
        const next = [...prev];
        next[index] = resp.data;
        return next;
      });
    } catch (error) {
      console.error("failed to rename workspace", error);
    }
  };

  /** Navigate to next session for a panel. */
  const nextSessionForPanel = async (index: number) => {
    const container = selectedContainers[index];
    if (!container) return;
    try {
      const resp = await api.listWorkspaces(container);
      const wsList = resp.data;
      if (wsList.length < 2) return;
      const currentId = panelSessionIds[index];
      const curIdx = wsList.findIndex((w) => w.session_id === currentId);
      const next = wsList[(curIdx + 1) % wsList.length];
      selectWorkspace(index, next);
    } catch (error) {
      console.error("failed to navigate to next session", error);
    }
  };

  /** Navigate to previous session for a panel. */
  const prevSessionForPanel = async (index: number) => {
    const container = selectedContainers[index];
    if (!container) return;
    try {
      const resp = await api.listWorkspaces(container);
      const wsList = resp.data;
      if (wsList.length < 2) return;
      const currentId = panelSessionIds[index];
      const curIdx = wsList.findIndex((w) => w.session_id === currentId);
      const prev = wsList[(curIdx - 1 + wsList.length) % wsList.length];
      selectWorkspace(index, prev);
    } catch (error) {
      console.error("failed to navigate to previous session", error);
    }
  };

  /** Switch to the last-used session for a panel. */
  const lastSessionForPanel = async (index: number) => {
    const container = selectedContainers[index];
    if (!container) return;
    try {
      const resp = await api.listWorkspaces(container);
      const currentId = panelSessionIds[index];
      const others = resp.data.filter((w) => w.session_id !== currentId);
      if (others.length === 0) return;
      others.sort((a, b) => {
        const aTime = a.last_attach_at ? new Date(a.last_attach_at).getTime() : 0;
        const bTime = b.last_attach_at ? new Date(b.last_attach_at).getTime() : 0;
        return bTime - aTime;
      });
      selectWorkspace(index, others[0]);
    } catch (error) {
      console.error("failed to switch to last session", error);
    }
  };

  /** Rename the currently connected session for a panel. */
  const renameCurrentSession = async (index: number, newName: string) => {
    const container = selectedContainers[index];
    const currentId = panelSessionIds[index];
    if (!container || !currentId) return;
    try {
      const resp = await api.listWorkspaces(container);
      const ws = resp.data.find((w) => w.session_id === currentId);
      if (!ws) return;
      await api.renameWorkspace(container, ws.id, newName);
      setPanelSessionNames((prev) => {
        const next = [...prev];
        next[index] = newName;
        return next;
      });
    } catch (error) {
      console.error("failed to rename session", error);
    }
  };

  /** Delete a workspace. */
  const deleteWorkspaceHandler = async (index: number, id: string) => {
    const container = selectedContainers[index];
    if (!container) return;
    try {
      await api.deleteWorkspace(container, id);
      // Refresh the workspace list.
      const resp = await api.listWorkspaces(container);
      if (resp.data.length >= 1) {
        setPanelWorkspaces((prev) => {
          const next = [...prev];
          next[index] = resp.data;
          return next;
        });
      } else {
        // None left — create a fresh one.
        const ws = await api.getTerminalWorkspace(container);
        setPanelSessionIds((prev) => {
          const next = [...prev];
          next[index] = ws.session_id;
          return next;
        });
        setPanelSessionNames((prev) => {
          const next = [...prev];
          next[index] = ws.display_name ?? "";
          return next;
        });
        setPanelWorkspaces((prev) => {
          const next = [...prev];
          next[index] = null;
          return next;
        });
      }
    } catch (error) {
      console.error("failed to delete workspace", error);
    }
  };

  /** Return to the session picker for a panel. */
  const showPickerForPanel = async (index: number) => {
    const container = selectedContainers[index];
    if (!container) return;
    // Clear session to disconnect terminal.
    setPanelSessionIds((prev) => {
      const next = [...prev];
      next[index] = "";
      return next;
    });
    try {
      const resp = await api.listWorkspaces(container);
      setPanelWorkspaces((prev) => {
        const next = [...prev];
        next[index] = resp.data.length >= 1 ? resp.data : null;
        return next;
      });
      setPanelWarnings((prev) => {
        const next = [...prev];
        next[index] = resp.warning ?? null;
        return next;
      });
      // If 0 workspaces, re-resolve via normal flow.
      if (resp.data.length < 1) {
        resolvedRef.current.delete(index);
        setSelectedContainers((prev) => [...prev]);
      }
    } catch {
      resolvedRef.current.delete(index);
      setSelectedContainers((prev) => [...prev]);
    }
  };

  const retryWorkspace = (index: number) => {
    resolvedRef.current.delete(index);
    setWorkspaceErrors((prev) => {
      const next = [...prev];
      next[index] = false;
      return next;
    });
    setPanelSessionIds((prev) => {
      const next = [...prev];
      next[index] = "";
      return next;
    });
    // Force re-trigger of the useEffect by updating selectedContainers identity.
    setSelectedContainers((prev) => [...prev]);
  };

  const reconnectPanel = async (index: number) => {
    const container = selectedContainers[index];
    const sid = panelSessionIds[index];
    if (!container || !sid) return;

    setReconnectingPanels((prev) => {
      const next = [...prev];
      next[index] = true;
      return next;
    });

    try {
      await api.reconnectTerminal(container, sid);
      // Increment reconnectKey to trigger the useEffect re-run with the
      // SAME sessionId — tmux reattaches and preserves shell state.
      setReconnectKeys((prev) => {
        const next = [...prev];
        next[index] = (next[index] ?? 0) + 1;
        return next;
      });
    } catch (error) {
      console.error("failed to reconnect terminal session", error);
    } finally {
      setReconnectingPanels((prev) => {
        const next = [...prev];
        next[index] = false;
        return next;
      });
    }
  };

  return (
    <section className="page-section terminals-page">
      <header className="page-header">
        <p className="path">~/soyeht/admin/terminals</p>
        <h1>terminals</h1>
        <p className="subtitle">// select a container in each panel to open a terminal</p>
      </header>

      <div className="terminal-grid">
        {panelIndexes.map((index) => {
          const workspaces = panelWorkspaces[index] ?? null;
          const warning = panelWarnings[index] ?? null;
          return workspaces ? (
            <article key={`panel-${index}`} className="terminal-panel" data-testid={`session-picker-${index}`}>
              <div className="terminal-toolbar">
                <select
                  value={selectedContainers[index] ?? ""}
                  onChange={(e) => updatePanelContainer(index, e.target.value)}
                >
                  <option value="">-- select --</option>
                  {containers.map((c) => (
                    <option key={c} value={c}>{c}</option>
                  ))}
                </select>
              </div>
              <SessionPicker
                workspaces={workspaces}
                warning={warning}
                onSelect={(ws) => selectWorkspace(index, ws)}
                onCreate={(name) => void createAndConnect(index, name)}
                onRename={(id, name) => void renameWorkspaceHandler(index, id, name)}
                onDelete={(id) => void deleteWorkspaceHandler(index, id)}
              />
            </article>
          ) : (
            <TerminalPanel
              key={`panel-${index}`}
              panelIndex={index}
              container={selectedContainers[index] ?? ""}
              sessionId={panelSessionIds[index] ?? ""}
              fontSize={fontSizes[index] ?? 12}
              isReconnecting={reconnectingPanels[index] ?? false}
              isActive={index === activePanel}
              onActivate={() => setActivePanel(index)}
              containers={containers}
              onContainerChange={(value) => updatePanelContainer(index, value)}
              onFontChange={(delta) => updateFont(index, delta)}
              onReconnect={() => void reconnectPanel(index)}
              reconnectKey={reconnectKeys[index] ?? 0}
              workspaceError={workspaceErrors[index] ?? false}
              onRetryWorkspace={() => retryWorkspace(index)}
              onShowPicker={() => void showPickerForPanel(index)}
              currentSessionName={panelSessionNames[index] ?? ""}
              onNewSession={(name) => void createAndConnect(index, name)}
              onNextSession={() => void nextSessionForPanel(index)}
              onPrevSession={() => void prevSessionForPanel(index)}
              onLastSession={() => void lastSessionForPanel(index)}
              onRenameSession={(newName) => void renameCurrentSession(index, newName)}
            />
          );
        })}
      </div>

      <div className="add-terminals-row">
        <button type="button" onClick={() => setPanelCount((prev) => prev + 1)}>
          <span>+</span>
          <span>add-terminal</span>
        </button>
      </div>
    </section>
  );
}
