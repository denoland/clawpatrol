import { useEffect, useMemo, useRef, useState } from "react";
import { type LogEntry, type LogLevel, type LogsResp } from "../lib/api";
import { fmtDateTime } from "../lib/format";

// Plugin diagnostic log tail. Streams from /api/logs/stream over SSE;
// falls back to the static /api/logs snapshot for the initial backlog
// + on connection errors. Filters apply client-side so the user can
// flip between min severities without dropping the SSE subscription —
// the server already ships everything at the dashboard's chosen
// resolution (default debug).

const LEVELS: LogLevel[] = ["debug", "info", "warn", "error"];
const LEVEL_RANK: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const LEVEL_COLOR: Record<LogLevel, string> = {
  debug: "text-[#a3a3a3]",
  info: "text-[#525252]",
  warn: "text-[#c2410c]",
  error: "text-[#dc2626]",
};

const LEVEL_BADGE: Record<LogLevel, string> = {
  debug: "bg-[#f5f5f5] text-[#737373]",
  info: "bg-[#eff6ff] text-[#1d4ed8]",
  warn: "bg-[#fef3c7] text-[#a16207]",
  error: "bg-[#fee2e2] text-[#b91c1c]",
};

export function LogsPage({ onBack }: { onBack: () => void }) {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [knownPlugins, setKnownPlugins] = useState<string[]>([]);
  const [minLevel, setMinLevel] = useState<LogLevel>("info");
  const [pluginFilter, setPluginFilter] = useState<string>("");
  const [paused, setPaused] = useState(false);
  const [bufferCap, setBufferCap] = useState(0);
  const [drops, setDrops] = useState(0);
  const [streaming, setStreaming] = useState(false);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  // SSE subscription. Server ships a `backlog` event (single batch)
  // up front, then per-entry `data:` messages. Same shape as
  // /api/events — see LiveRequests for the comment about why we
  // batch through requestAnimationFrame.
  useEffect(() => {
    const es = new EventSource("/api/logs/stream");
    let pending: LogEntry[] = [];
    let raf = 0;
    const cap = 2000;
    const flush = () => {
      raf = 0;
      if (pending.length === 0) return;
      const batch = pending;
      pending = [];
      if (pausedRef.current) return;
      setEntries((prev) => {
        const next = prev.concat(batch);
        if (next.length > cap) return next.slice(next.length - cap);
        return next;
      });
    };
    es.addEventListener("backlog", (e) => {
      try {
        const arr = JSON.parse((e as MessageEvent).data) as LogEntry[];
        setEntries((prev) => {
          const next = prev.concat(arr);
          if (next.length > cap) return next.slice(next.length - cap);
          return next;
        });
      } catch {
        /* ignore */
      }
    });
    es.onmessage = (e) => {
      try {
        const entry = JSON.parse(e.data) as LogEntry;
        pending.push(entry);
        if (raf === 0) raf = requestAnimationFrame(flush);
      } catch {
        /* ignore */
      }
    };
    es.onopen = () => setStreaming(true);
    es.onerror = () => setStreaming(false);
    return () => {
      es.close();
      if (raf !== 0) cancelAnimationFrame(raf);
    };
  }, []);

  // Periodically refresh meta (buffer cap, drops, plugins). Static
  // snapshot, cheap; runs every 5 s so the filter dropdown picks up
  // newly-active plugins as soon as they emit.
  useEffect(() => {
    let cancelled = false;
    const load = () => {
      fetch("/api/logs?meta=1&limit=1")
        .then((r) => r.json() as Promise<LogsResp>)
        .then((r) => {
          if (cancelled) return;
          setBufferCap(r.buffer_cap || 0);
          setDrops(r.drops || 0);
          if (r.plugins) {
            setKnownPlugins((prev) => mergeUnique(prev, r.plugins ?? []));
          }
        })
        .catch(() => {});
    };
    load();
    const t = setInterval(load, 5000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  // Surface plugins seen in the live stream too — covers the case
  // where a plugin first logs after the dashboard loaded.
  useEffect(() => {
    if (entries.length === 0) return;
    const seen = new Set<string>();
    for (const e of entries) if (e.plugin) seen.add(e.plugin);
    setKnownPlugins((prev) => mergeUnique(prev, Array.from(seen)));
  }, [entries]);

  const filtered = useMemo(() => {
    const minRank = LEVEL_RANK[minLevel];
    const wantPlugin = pluginFilter;
    return entries.filter((e) => {
      if (LEVEL_RANK[e.level] < minRank) return false;
      if (wantPlugin && e.plugin !== wantPlugin) return false;
      return true;
    });
  }, [entries, minLevel, pluginFilter]);

  function clear() {
    setEntries([]);
  }

  return (
    <main className="flex-1 mx-auto w-full max-w-[1200px] px-4 sm:px-6 py-8 space-y-4">
      <div className="flex items-center gap-4 flex-wrap">
        <button
          onClick={onBack}
          className="text-[#525252] hover:text-[#171717] text-[14px]"
          title="back"
        >
          ←
        </button>
        <h1 className="font-serif text-[32px] leading-none tracking-tight text-[#171717]">
          plugin logs
        </h1>
        <span
          className="flex items-center gap-1.5 text-[11px] text-[#737373]"
          title="SSE live tail"
        >
          <span
            className={
              "inline-block w-[7px] h-[7px] rounded-full " +
              (streaming ? "bg-[#22c55e]" : "bg-[#d4d4d4]")
            }
          />
          {streaming ? "live" : "reconnecting"}
        </span>
      </div>

      <div className="bg-white border border-[#e5e5e5] rounded p-3 flex flex-wrap items-center gap-3 text-[12px]">
        <label className="flex items-center gap-2">
          <span className="text-[#737373]">min severity</span>
          <select
            value={minLevel}
            onChange={(e) => setMinLevel(e.target.value as LogLevel)}
            className="border border-[#e5e5e5] rounded px-2 py-1 bg-white"
          >
            {LEVELS.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2">
          <span className="text-[#737373]">plugin</span>
          <select
            value={pluginFilter}
            onChange={(e) => setPluginFilter(e.target.value)}
            className="border border-[#e5e5e5] rounded px-2 py-1 bg-white min-w-[160px]"
          >
            <option value="">all</option>
            {knownPlugins.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        <button
          onClick={() => setPaused((p) => !p)}
          className="border border-[#e5e5e5] rounded px-2 py-1 hover:border-[#171717] hover:text-[#171717]"
          title={paused ? "resume live updates" : "freeze the tail"}
        >
          {paused ? "▶ resume" : "❚❚ pause"}
        </button>
        <button
          onClick={clear}
          className="border border-[#e5e5e5] rounded px-2 py-1 hover:border-[#171717] hover:text-[#171717]"
          title="clear visible entries (does not flush the server buffer)"
        >
          clear
        </button>
        <div className="ml-auto text-[11px] text-[#a3a3a3] tabular-nums">
          {filtered.length} / {entries.length} entries · buffer {bufferCap}
          {drops > 0 ? ` · ${drops.toLocaleString()} dropped` : ""}
        </div>
      </div>

      <div className="bg-white border border-[#e5e5e5] rounded overflow-hidden">
        <div className="grid grid-cols-[200px_70px_220px_1fr] text-[10px] uppercase tracking-[.12em] text-[#a3a3a3] px-3 py-2 border-b border-[#e5e5e5]">
          <div>time</div>
          <div>level</div>
          <div>plugin</div>
          <div>message</div>
        </div>
        <div className="max-h-[70vh] overflow-y-auto font-mono text-[12px]">
          {filtered.length === 0 ? (
            <div className="px-3 py-6 text-center text-[#a3a3a3]">
              no log entries match the current filters
            </div>
          ) : (
            filtered
              .slice()
              .reverse()
              .map((e, i) => <LogRow key={i} entry={e} />)
          )}
        </div>
      </div>
    </main>
  );
}

function LogRow({ entry }: { entry: LogEntry }) {
  const [open, setOpen] = useState(false);
  const hasFields = entry.fields && Object.keys(entry.fields).length > 0;
  const hasContext = entry.req_id || entry.agent_ip;
  const expandable = hasFields || hasContext;
  return (
    <div
      className={
        "grid grid-cols-[200px_70px_220px_1fr] px-3 py-1.5 border-b border-[#f5f5f5] " +
        (expandable ? "cursor-pointer hover:bg-[#fafafa]" : "")
      }
      onClick={() => expandable && setOpen((o) => !o)}
    >
      <div className="text-[#737373] tabular-nums">{fmtDateTime(entry.ts)}</div>
      <div>
        <span
          className={
            "inline-block px-1.5 py-[1px] rounded text-[10px] uppercase tracking-wide " +
            LEVEL_BADGE[entry.level]
          }
        >
          {entry.level}
        </span>
      </div>
      <div className="text-[#525252] truncate">{entry.plugin || "—"}</div>
      <div className={LEVEL_COLOR[entry.level] + " break-words"}>
        {entry.msg}
        {open && (
          <div className="mt-1 text-[11px] text-[#737373] space-y-0.5">
            {entry.req_id && (
              <div>
                req_id:{" "}
                <a
                  href={`#/request/${encodeURIComponent(entry.req_id)}`}
                  className="text-[#1d4ed8] hover:underline"
                  onClick={(ev) => ev.stopPropagation()}
                >
                  {entry.req_id}
                </a>
              </div>
            )}
            {entry.agent_ip && <div>agent: {entry.agent_ip}</div>}
            {hasFields &&
              Object.entries(entry.fields ?? {}).map(([k, v]) => (
                <div key={k} className="break-all">
                  {k}: <span className="text-[#525252]">{formatField(v)}</span>
                </div>
              ))}
          </div>
        )}
      </div>
    </div>
  );
}

function formatField(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

function mergeUnique(prev: string[], next: string[]): string[] {
  if (next.length === 0) return prev;
  const seen = new Set(prev);
  let changed = false;
  for (const n of next) {
    if (!seen.has(n)) {
      seen.add(n);
      changed = true;
    }
  }
  if (!changed) return prev;
  return Array.from(seen).sort();
}
