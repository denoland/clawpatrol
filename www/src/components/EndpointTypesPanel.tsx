import { useEffect, useState } from "react";
import { getEndpointTypes, type EndpointTypeInfo } from "../lib/api";
import { RulesEditor } from "./RulesEditor";

// EndpointTypesPanel surfaces every registered endpoint plugin so
// operators can discover types not yet in their config. Clicking a
// not-configured card opens the gateway.hcl editor with that plugin's
// example block appended at the bottom — operator edits names / hosts
// before saving.
//
// "In your config" cards are non-clickable: editing existing endpoints
// happens through the regular Rules pencil, which opens the same
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

  return (
    <div className="bg-white border border-[#e5e5e5] rounded">
      <div className="flex items-center px-4 py-2.5 border-b border-[#e5e5e5]">
        <span className="text-[10px] uppercase tracking-[.12em] text-[#a3a3a3]">
          Endpoint types
        </span>
        <span className="ml-2 text-[10px] text-[#a3a3a3]">
          discover what the gateway can intercept
        </span>
      </div>
      {err && <div className="px-4 py-3 text-[11px] text-red-600">{err}</div>}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-px bg-[#f5f5f5]">
        {rows.map((r) => (
          <Card
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
    </div>
  );
}

function Card({
  row,
  onAdd,
}: {
  row: EndpointTypeInfo;
  onAdd: () => void;
}) {
  const clickable = !row.in_config && !!row.example_hcl;
  return (
    <div
      onClick={clickable ? onAdd : undefined}
      className={
        "bg-white px-4 py-3 flex flex-col gap-1 min-w-0 transition-colors" +
        (clickable
          ? " cursor-pointer hover:bg-[#f9f9f9]"
          : " opacity-70")
      }
      title={clickable ? "click to add an example block to gateway.hcl" : undefined}
    >
      <div className="flex items-center gap-2 min-w-0">
        <span className="text-[12px] font-mono font-semibold text-[#171717] truncate">
          {row.type}
        </span>
        <FamilyBadge family={row.family} />
        <span className="ml-auto text-[10px] uppercase tracking-[.09em] text-[#a3a3a3] flex-shrink-0">
          {row.in_config ? "in config" : "+ add"}
        </span>
      </div>
      {row.description && (
        <div className="text-[11px] text-[#525252] leading-snug">
          {row.description}
        </div>
      )}
    </div>
  );
}

const FAMILY_COLORS: Record<string, string> = {
  https: "bg-[#dbeafe] text-[#1e40af]",
  sql: "bg-[#fef3c7] text-[#92400e]",
  k8s: "bg-[#dcfce7] text-[#166534]",
  ssh: "bg-[#f3e8ff] text-[#6b21a8]",
};

function FamilyBadge({ family }: { family: string }) {
  const cls = FAMILY_COLORS[family] ?? "bg-[#f5f5f5] text-[#525252]";
  return (
    <span className={"text-[9px] font-mono uppercase tracking-[.06em] px-1.5 py-0.5 rounded flex-shrink-0 " + cls}>
      {family}
    </span>
  );
}
