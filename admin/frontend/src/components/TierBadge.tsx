import type { ClawTier } from "../lib/types";

/// Pill that labels a claw's catalog tier.
///
/// Colors intentionally mirror semantic meaning in the store UI:
///   supported → green  (ready to install from golden image)
///   available → yellow (installable but first build takes ~10 min)
///   detected  → gray   (discovered but not yet verified)
///   catalog   → outline (raw listing; no install)
///
/// Uses the same visual language as `.claw-lang-badge` (border + small caps)
/// so the two badges sit next to each other without fighting visually.
export type TierBadgeProps = {
  tier: ClawTier | undefined;
  /// When true, renders a smaller variant for dense lists.
  compact?: boolean;
};

const TIER_STYLES: Record<ClawTier, { color: string; label: string; title: string }> = {
  supported: {
    color: "#22c55e",
    label: "supported",
    title: "Fully supported — pre-built golden image, installs in seconds.",
  },
  available: {
    color: "#f59e0b",
    label: "available",
    title: "Available — install plan verified, first-time build takes ~10 min.",
  },
  detected: {
    color: "var(--text-muted)",
    label: "detected",
    title: "Detected upstream repo — not yet verified to install cleanly.",
  },
  catalog: {
    color: "var(--text-muted)",
    label: "catalog",
    title: "Catalog listing — no install path available yet.",
  },
};

export function TierBadge({ tier, compact = false }: TierBadgeProps) {
  // Unknown or missing tier: render nothing so legacy rows stay clean.
  if (!tier || !(tier in TIER_STYLES)) {
    return null;
  }
  const style = TIER_STYLES[tier];
  return (
    <span
      className="claw-lang-badge"
      title={style.title}
      style={{
        borderColor: style.color,
        color: style.color,
        marginLeft: 0,
        ...(compact ? { fontSize: "9px", padding: "0 4px" } : {}),
      }}
    >
      {style.label}
    </span>
  );
}
