import { IntegrationIcon } from "./Logos";

// Overlapping circles a la GitHub avatar stack. Items carry both the
// credential bare-name (id) and the plugin type — IntegrationIcon uses
// the type to pick a brand logo, falling back to the id for the
// claude/codex/github built-ins where the bare name happens to match
// the brand.
export function IntegrationStack({
  items,
  size = 20,
}: {
  items: { id: string; type?: string }[];
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
          <span style={{ width: inner, height: inner, display: "inline-flex", color: "#171717" }}>
            <IntegrationIcon id={it.id} type={it.type} className="w-full h-full" />
          </span>
        </span>
      ))}
    </div>
  );
}
