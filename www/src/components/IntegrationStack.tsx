import * as React from "react";
import { IntegrationIcon } from "./Logos";

// Overlapping circles a la GitHub avatar stack. Items carry both the
// credential bare-name (id) and the plugin type — IntegrationIcon uses
// the type to pick a brand logo, falling back to the id for the
// claude/codex/github built-ins where the bare name happens to match
// the brand. avatar_url, when present, replaces the brand logo with
// the connected user's PFP (e.g. github avatar) so two devices in
// different profiles connected to different accounts are
// visually distinguishable in the agents table.
export function IntegrationStack({
  items,
  size = 20,
}: {
  items: { id: string; type?: string; avatar_url?: string }[];
  size?: number;
}) {
  if (!items?.length) return <span className="text-[10px] text-[#a3a3a3]">—</span>;
  const inner = Math.round(size * 0.6);
  return (
    <div className="flex items-center">
      {items.map((it, i) => (
        <span
          key={it.id}
          title={it.id}
          className="rounded-full bg-white border border-[#e5e5e5] flex items-center justify-center overflow-hidden"
          style={{
            width: size,
            height: size,
            marginLeft: i === 0 ? 0 : -size * 0.35,
            zIndex: items.length - i,
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
            <span style={{ width: inner, height: inner, display: "inline-flex", color: "#171717" }}>
              <IntegrationIcon id={it.id} type={it.type} className="w-full h-full" />
            </span>
          )}
        </span>
      ))}
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
      <span style={{ width: inner, height: inner, display: "inline-flex", color: "#171717" }}>
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
