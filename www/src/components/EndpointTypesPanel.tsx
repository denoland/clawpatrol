import { useEffect, useState } from "react";
import { getEndpointTypes, type EndpointTypeInfo } from "../lib/api";
import { RulesEditor } from "./RulesEditor";

// EndpointTypesPanel surfaces every registered endpoint plugin so
// operators can discover types not yet in their config. Compact pill
// row — keeps the device page from ballooning. Clicking a not-
// configured pill opens gateway.hcl with the plugin's example block
// appended at the bottom; operator edits names / hosts before saving.
//
// In-config pills are dimmed and not clickable: editing existing
// endpoints happens through the Rules pencil, which opens the same
// editor without an append.
export function EndpointTypesPanel() {
  const [rows, setRows] = useState<EndpointTypeInfo[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [appending, setAppending] = useState<string | null>(null);

  function reload() {
    getEndpointTypes()
      .then(setRows)
      .catch((e: Error) => setErr(String(e.message ?? e)));
  }
  useEffect(reload, []);

  if (err) {
    return <div className="text-[11px] text-red-600 px-1">{err}</div>;
  }
  if (rows.length === 0) return null;

  return (
    <>
      <div className="flex items-center flex-wrap gap-1.5 px-1">
        <span className="text-[10px] uppercase tracking-[.12em] text-[#a3a3a3] mr-1">
          Endpoint types
        </span>
        {rows.map((r) => (
          <Pill
            key={r.type}
            row={r}
            onAdd={() => setAppending(r.example_hcl ?? "")}
          />
        ))}
      </div>
      {appending !== null && (
        <RulesEditor
          initialAppend={appending}
          onClose={() => setAppending(null)}
          onSaved={() => {
            reload();
            setAppending(null);
          }}
        />
      )}
    </>
  );
}

const FAMILY_DOT: Record<string, string> = {
  https: "bg-[#3b82f6]",
  sql: "bg-[#d97706]",
  k8s: "bg-[#16a34a]",
  ssh: "bg-[#9333ea]",
};

function Pill({ row, onAdd }: { row: EndpointTypeInfo; onAdd: () => void }) {
  const clickable = !row.in_config && !!row.example_hcl;
  const dot = FAMILY_DOT[row.family] ?? "bg-[#a3a3a3]";
  const title = row.description
    ? `${row.family} · ${row.description}` +
      (clickable ? "\n\nclick to add an example block to gateway.hcl" : "")
    : row.family;
  const cls = row.in_config
    ? "border-[#e5e5e5] text-[#a3a3a3]"
    : clickable
      ? "border-[#e5e5e5] text-[#525252] hover:border-[#171717] hover:text-[#171717] cursor-pointer"
      : "border-[#e5e5e5] text-[#a3a3a3]";
  return (
    <button
      type="button"
      disabled={!clickable}
      onClick={clickable ? onAdd : undefined}
      title={title}
      className={
        "inline-flex items-center gap-1.5 text-[11px] font-mono px-2 py-1 border rounded-full transition-colors " +
        cls
      }
    >
      <span className={"w-1.5 h-1.5 rounded-full flex-shrink-0 " + dot} />
      <span>{row.type}</span>
      {!row.in_config && clickable && (
        <span className="text-[#a3a3a3]">+</span>
      )}
    </button>
  );
}
