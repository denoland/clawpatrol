import * as React from "react";
import { IntegrationIcon } from "./Logos";

// Compact integration display for the agents table.
//
// Items split into two visual groups:
//
//   1. Needs-action items (unconfigured / expired credentials) — shown
//      first, with a red ring, side-by-side (no overlap). These are
//      what operators must act on, so they get the visual priority and
//      are clickable: clicking calls onItemClick(id), which the parent
//      routes into the connect flow.
//   2. Configured items — stacked à la GitHub avatar group, overlapping
//      so a long list stays compact.
//
// avatar_url, when present, replaces the brand logo with the connected
// account's PFP (e.g. github avatar) so two devices connected to
// different accounts are visually distinguishable.
export type StackItem = {
  id: string;
  type?: string;
  avatar_url?: string;
  needsAction?: boolean;
};

export function IntegrationStack({
  items,
  size = 20,
  onItemClick,
}: {
  items: StackItem[];
  size?: number;
  onItemClick?: (id: string) => void;
}) {
  if (!items?.length) return <span className="text-2xs text-text-subtle">—</span>;
  const inner = Math.round(size * 0.6);
  // Stable sort: needs-action first, original order otherwise. The
  // server already returns the per-profile credential list in
  // alphabetical order, so we preserve that within each bucket.
  const sorted = items
    .map((it, i) => ({ it, i }))
    .sort((a, b) => {
      const an = a.it.needsAction ? 0 : 1;
      const bn = b.it.needsAction ? 0 : 1;
      if (an !== bn) return an - bn;
      return a.i - b.i;
    })
    .map((x) => x.it);
  return (
    <div className="flex items-center">
      {sorted.map((it, i) => {
        const prev = i > 0 ? sorted[i - 1] : undefined;
        // Needs-action items: small positive gap so the red rings stay
        // legible. Configured items: stacked with a negative margin,
        // except the first one after a needs-action group, which
        // anchors at zero so the two groups don't visually fuse.
        const margin =
          i === 0
            ? 0
            : it.needsAction
              ? 4
              : prev?.needsAction
                ? 6
                : Math.round(-size * 0.35);
        const clickable = it.needsAction && onItemClick;
        return (
          <span
            key={it.id}
            title={it.needsAction ? `${it.id} — click to configure` : it.id}
            onClick={
              clickable
                ? (e) => {
                    e.stopPropagation();
                    onItemClick(it.id);
                  }
                : undefined
            }
            className={
              "rounded-full bg-canvas flex items-center justify-center overflow-hidden " +
              (it.needsAction ? "border-2 border-danger " : "border border-canvas-dark ") +
              (clickable ? "cursor-pointer hover:border-text" : "")
            }
            style={{
              width: size,
              height: size,
              marginLeft: margin,
              zIndex: sorted.length - i,
            }}
          >
            {it.avatar_url ? (
              <StackAvatar
                src={it.avatar_url}
                fallbackId={it.id}
                fallbackType={it.type}
                size={size}
                inner={inner}
              />
            ) : (
              <span
                style={{
                  width: inner,
                  height: inner,
                  display: "inline-flex",
                  color: "var(--color-text)",
                }}
              >
                <IntegrationIcon id={it.id} type={it.type} className="w-full h-full" />
              </span>
            )}
          </span>
        );
      })}
    </div>
  );
}

function StackAvatar({
  src,
  fallbackId,
  fallbackType,
  size,
  inner,
}: {
  src: string;
  fallbackId: string;
  fallbackType?: string;
  size: number;
  inner: number;
}) {
  const [broken, setBroken] = React.useState(false);
  if (broken) {
    return (
      <span
        style={{ width: inner, height: inner, display: "inline-flex", color: "var(--color-text)" }}
      >
        <IntegrationIcon id={fallbackId} type={fallbackType} className="w-full h-full" />
      </span>
    );
  }
  return (
    <img
      src={src}
      alt=""
      onError={() => setBroken(true)}
      style={{ width: size, height: size, objectFit: "cover" }}
    />
  );
}
