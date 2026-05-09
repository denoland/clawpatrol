import { useState, useEffect } from "react";
import { getAction, type Agent, type EventRecord } from "../lib/api";

export function RequestDetailPage({ id, agents }: { id: string; agents: Agent[] }) {
  const [ev, setEv] = useState<EventRecord | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getAction(id)
      .then(setEv)
      .catch((e) => setErr(e.message ?? "load failed"));
  }, [id]);

  if (err) {
    return (
      <Shell>
        <div className="text-[13px] text-[#dc2626]">{err}</div>
      </Shell>
    );
  }
  if (!ev) {
    return (
      <Shell>
        <div className="text-[12px] text-[#a3a3a3]">Loading...</div>
      </Shell>
    );
  }

  const t = new Date(ev.ts);
  const time =
    t.toLocaleDateString() +
    " " +
    t.toLocaleTimeString([], { hour12: false }) +
    "." +
    String(t.getMilliseconds()).padStart(3, "0");
  const status = ev.status || 0;
  const statusColor =
    status >= 500
      ? "text-[#dc2626]"
      : status >= 400
        ? "text-[#ea580c]"
        : status >= 300
          ? "text-[#ca8a04]"
          : status >= 200
            ? "text-[#16a34a]"
            : "text-[#737373]";
  const path = ev.path ?? "";
  const fullUrl = ev.host + (path.startsWith("/") ? "" : " ") + path;
  const hasReq = !!ev.req_body;
  const hasResp = !!ev.resp_body;
  const hasReqH = ev.req_headers && Object.keys(ev.req_headers).length > 0;
  const hasRespH = ev.resp_headers && Object.keys(ev.resp_headers).length > 0;
  const hasSections = hasReq || hasResp || hasReqH || hasRespH;

  return (
    <Shell
      agentIP={ev.agent_ip}
      agentName={agents.find((a) => a.ip === ev.agent_ip)?.hostname}
      requestId={ev.id}
    >
      {/* header */}
      <div className="bg-white border border-[#e5e5e5] rounded p-5 space-y-3">
        <div className="flex items-center gap-3 flex-wrap">
          <ModeIcon mode={ev.mode} />
          {ev.method && (
            <span className="text-[12px] uppercase font-semibold text-[#525252]">{ev.method}</span>
          )}
          <span className={"text-[13px] tabular-nums font-semibold " + statusColor}>
            {status || "\u2014"}
          </span>
          <span className="text-[13px] text-[#171717] break-all font-mono" title={fullUrl}>
            {fullUrl}
          </span>
        </div>
        <div className="flex items-center gap-4 text-[11px] text-[#737373] flex-wrap">
          <span>{time}</span>
          <span>{ev.ms}ms</span>
          {ev.agent_ip && <span>{ev.agent_ip}</span>}
        </div>
        {(ev.action || ev.reason) && (
          <div className="flex items-center gap-2 text-[11px]">
            {ev.action && (
              <span
                className={
                  "px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase " +
                  (ev.action === "deny"
                    ? "bg-[#fef2f2] text-[#dc2626]"
                    : "bg-[#f0fdf4] text-[#16a34a]")
                }
              >
                {ev.action}
              </span>
            )}
            {ev.reason && <span className="text-[#737373]">{ev.reason}</span>}
          </div>
        )}
      </div>

      {/* sections */}
      {hasSections ? (
        <div className="bg-white border border-[#e5e5e5] rounded divide-y divide-[#e5e5e5]">
          {hasReqH && (
            <Section title="Request headers">
              <Headers obj={ev.req_headers!} />
            </Section>
          )}
          {hasReq && (
            <Section title="Request body">
              <HttpBody text={ev.req_body!} />
            </Section>
          )}
          {hasRespH && (
            <Section title="Response headers">
              <Headers obj={ev.resp_headers!} />
            </Section>
          )}
          {hasResp && (
            <Section title={`Response body${status ? ` (${status})` : ""}`}>
              <HttpBody text={ev.resp_body!} />
            </Section>
          )}
        </div>
      ) : (
        <div className="bg-white border border-[#e5e5e5] rounded px-5 py-4 text-[12px] text-[#a3a3a3]">
          No request/response body captured
          {ev.mode === "splice" && " (spliced connection)"}
        </div>
      )}

      {/* footer */}
      <div className="flex items-center gap-6 text-[10px] text-[#a3a3a3] flex-wrap">
        {ev.in != null && ev.in > 0 && <span>in: {fmtBytes(ev.in)}</span>}
        {ev.out != null && ev.out > 0 && <span>out: {fmtBytes(ev.out)}</span>}
        {ev.req_sha && (
          <span className="font-mono" title={ev.req_sha}>
            req_sha: {ev.req_sha.slice(0, 12)}
          </span>
        )}
        {ev.resp_sha && (
          <span className="font-mono" title={ev.resp_sha}>
            resp_sha: {ev.resp_sha.slice(0, 12)}
          </span>
        )}
      </div>
    </Shell>
  );
}

// --- layout ---

function Breadcrumbs({
  agentIP,
  agentName,
  requestId,
}: {
  agentIP?: string;
  agentName?: string;
  requestId?: string;
}) {
  return (
    <nav className="flex items-baseline gap-2">
      <a href="#/" className="text-[13px] text-[#a3a3a3] hover:text-[#171717]">
        clawpatrol
      </a>
      {agentIP && (
        <>
          <span className="text-[13px] text-[#a3a3a3]">/</span>
          <a
            href={`#/device/${encodeURIComponent(agentIP)}`}
            className="text-[13px] text-[#a3a3a3] hover:text-[#171717]"
          >
            {agentName || agentIP}
          </a>
        </>
      )}
      {requestId && (
        <>
          <span className="text-[13px] text-[#a3a3a3]">/</span>
          <span className="text-[13px] text-[#525252] font-mono">{requestId.slice(0, 8)}</span>
        </>
      )}
    </nav>
  );
}

function Shell({
  children,
  agentIP,
  agentName,
  requestId,
}: {
  children: React.ReactNode;
  agentIP?: string;
  agentName?: string;
  requestId?: string;
}) {
  return (
    <main className="mx-auto w-full max-w-[1100px] px-4 sm:px-6 py-5 space-y-5">
      <Breadcrumbs agentIP={agentIP} agentName={agentName} requestId={requestId} />
      {children}
    </main>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <details open>
      <summary className="cursor-pointer px-4 py-2.5 text-[10px] uppercase tracking-wider font-medium text-[#a3a3a3] hover:text-[#525252] select-none">
        {title}
      </summary>
      <div className="border-t border-[#f5f5f5]">{children}</div>
    </details>
  );
}

// --- headers ---

const SENSITIVE = /auth|token|secret|key|password|cookie/i;

function Headers({ obj }: { obj: Record<string, string> }) {
  return (
    <pre className="overflow-auto whitespace-pre-wrap break-all px-4 py-3 font-mono text-[11px] leading-relaxed">
      {Object.entries(obj).map(([k, v]) => (
        <div key={k}>
          <span className="font-semibold text-[#171717]">{k}</span>
          <span className="text-[#a3a3a3]">: </span>
          {SENSITIVE.test(k) ? (
            <span className="text-[#a3a3a3]">{"*".repeat(Math.min(v.length, 24))}</span>
          ) : (
            <span className="text-[#525252]">{v}</span>
          )}
        </div>
      ))}
    </pre>
  );
}

// --- body rendering (JSON tree / SSE / plain) ---

// tryParseJSON attempts JSON.parse; on failure (e.g. truncated at
// the 4KB sampler cap) walks backward to find the last position
// where closing all open containers yields valid JSON.
function tryParseJSON(text: string): {
  parsed: unknown;
  truncated: boolean;
} | null {
  try {
    return { parsed: JSON.parse(text), truncated: false };
  } catch {
    /* fall through */
  }
  // Walk the string tracking container depth, ignoring string
  // interiors. At each position where we're outside a string
  // and just finished a complete value (after , or : or [ or {),
  // record it as a candidate cut point.
  let inStr = false;
  let esc = false;
  const stack: string[] = [];
  let lastGoodCut = -1;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (esc) {
      esc = false;
      continue;
    }
    if (ch === "\\") {
      esc = true;
      continue;
    }
    if (ch === '"') {
      inStr = !inStr;
      continue;
    }
    if (inStr) continue;
    if (ch === "{") stack.push("}");
    else if (ch === "[") stack.push("]");
    else if (ch === "}" || ch === "]") {
      stack.pop();
      lastGoodCut = i + 1;
    } else if (ch === ",") {
      lastGoodCut = i;
    }
  }
  // Try cutting at each candidate, newest first
  for (let cut = lastGoodCut; cut > 0; cut--) {
    // Re-scan up to cut to get the stack state
    const st: string[] = [];
    let ins = false;
    let es = false;
    for (let i = 0; i < cut; i++) {
      const c = text[i];
      if (es) {
        es = false;
        continue;
      }
      if (c === "\\") {
        es = true;
        continue;
      }
      if (c === '"') {
        ins = !ins;
        continue;
      }
      if (ins) continue;
      if (c === "{") st.push("}");
      else if (c === "[") st.push("]");
      else if (c === "}" || c === "]") st.pop();
    }
    let attempt = text.slice(0, cut);
    // Strip trailing comma
    if (attempt.endsWith(",")) {
      attempt = attempt.slice(0, -1);
    }
    attempt += st.reverse().join("");
    try {
      return { parsed: JSON.parse(attempt), truncated: true };
    } catch {
      continue;
    }
  }
  return null;
}

// SSE bodies (text/event-stream) are blocks of `event:`/`data:` lines
// separated by blank lines. Returns null when the body doesn't look
// like SSE.
type SseEvent = { type?: string; id?: string; data: string };
function parseSSE(text: string): SseEvent[] | null {
  if (!/^(event|data|id|retry):/m.test(text)) return null;
  const events: SseEvent[] = [];
  for (const block of text.split(/\r?\n\r?\n+/)) {
    if (!block.trim()) continue;
    const ev: SseEvent = { data: "" };
    let valid = false;
    for (const line of block.split(/\r?\n/)) {
      const idx = line.indexOf(":");
      if (idx <= 0) continue;
      const k = line.slice(0, idx);
      let v = line.slice(idx + 1);
      if (v.startsWith(" ")) v = v.slice(1);
      if (k === "event") {
        ev.type = v;
        valid = true;
      } else if (k === "data") {
        ev.data = ev.data ? ev.data + "\n" + v : v;
        valid = true;
      } else if (k === "id") ev.id = v;
    }
    if (valid) events.push(ev);
  }
  return events.length > 0 ? events : null;
}

function HttpBody({ text }: { text: string }) {
  if (!text) return <div className="px-4 py-3 text-[11px] text-[#a3a3a3]">(empty)</div>;
  const result = tryParseJSON(text);
  if (result) {
    return (
      <div className="overflow-auto px-4 py-3 font-mono text-[11px] leading-relaxed">
        <JsonNode value={result.parsed} />
        {result.truncated && <div className="mt-2 text-[10px] text-[#a3a3a3]">(truncated)</div>}
      </div>
    );
  }
  const sse = parseSSE(text);
  if (sse) {
    return (
      <div className="overflow-auto px-4 py-3 font-mono text-[11px] leading-relaxed space-y-3">
        {sse.map((e, i) => {
          const dataJson = tryParseJSON(e.data);
          return (
            <div key={i}>
              {e.type && (
                <div className="text-[10px] uppercase tracking-[.12em] text-[#a3a3a3] mb-1">
                  event:{" "}
                  <span className="normal-case tracking-normal text-[#525252]">{e.type}</span>
                </div>
              )}
              {dataJson ? (
                <>
                  <JsonNode value={dataJson.parsed} />
                  {dataJson.truncated && (
                    <div className="mt-1 text-[10px] text-[#a3a3a3]">(truncated)</div>
                  )}
                </>
              ) : (
                <pre className="whitespace-pre-wrap break-all text-[#525252]">{e.data}</pre>
              )}
            </div>
          );
        })}
      </div>
    );
  }
  return (
    <pre className="overflow-auto whitespace-pre-wrap break-all px-4 py-3 font-mono text-[11px] text-[#525252]">
      {text}
    </pre>
  );
}

// --- JSON tree (ported from unclaw) ---

const LONG_STRING = 120;

function JsonNode({ value }: { value: unknown }) {
  if (value === null) {
    return <span className="font-semibold text-[#a3a3a3]">null</span>;
  }
  if (typeof value === "boolean") {
    return <span className="font-semibold text-[#7c3aed]">{String(value)}</span>;
  }
  if (typeof value === "number") {
    return <span className="text-[#2563eb]">{String(value)}</span>;
  }
  if (typeof value === "string") {
    return <StringNode value={value} />;
  }
  if (Array.isArray(value)) {
    return (
      <Collapsible bracket={["[", "]"]} count={value.length}>
        {value.map((v, i) => (
          <div key={i} className="pl-5">
            <JsonNode value={v} />
            {i < value.length - 1 && ","}
          </div>
        ))}
      </Collapsible>
    );
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    return (
      <Collapsible bracket={["{", "}"]} count={entries.length}>
        {entries.map(([k, v], i) => (
          <div key={k} className="pl-5">
            <span className="text-[#be123c]">{JSON.stringify(k)}</span>
            {": "}
            <JsonNode value={v} />
            {i < entries.length - 1 && ","}
          </div>
        ))}
      </Collapsible>
    );
  }
  return <span>{String(value)}</span>;
}

function StringNode({ value }: { value: string }) {
  const raw = JSON.stringify(value);
  const long = raw.length > LONG_STRING;
  const [expanded, setExpanded] = useState(!long);

  if (!long) {
    return <span className="text-[#15803d]">{raw}</span>;
  }
  if (!expanded) {
    return (
      <span>
        <span className="text-[#15803d]">{raw.slice(0, LONG_STRING)}</span>
        <button onClick={() => setExpanded(true)} className="ml-1 text-[#2563eb] hover:underline">
          +{raw.length - LONG_STRING} more
        </button>
      </span>
    );
  }
  const inner = raw.slice(1, -1);
  const lines = inner.split("\\n");
  return (
    <span className="text-[#15803d]">
      {'"'}
      {lines.map((line, i) => (
        <span key={i}>
          {line}
          {i < lines.length - 1 && (
            <>
              <span className="text-[#a3a3a3]">\n</span>
              <br />
            </>
          )}
        </span>
      ))}
      {'"'}
      <button onClick={() => setExpanded(false)} className="ml-1 text-[#2563eb] hover:underline">
        less
      </button>
    </span>
  );
}

function Collapsible({
  bracket,
  count,
  children,
}: {
  bracket: [string, string];
  count: number;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(true);
  if (count === 0) {
    return (
      <span>
        {bracket[0]}
        {bracket[1]}
      </span>
    );
  }
  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="text-[#a3a3a3] hover:text-[#525252]">
        {bracket[0]} <span className="text-[#2563eb]">{count} items</span> {bracket[1]}
      </button>
    );
  }
  return (
    <span>
      <button onClick={() => setOpen(false)} className="hover:text-[#a3a3a3]">
        {bracket[0]}
      </button>
      {children}
      <div>{bracket[1]}</div>
    </span>
  );
}

// --- utils ---

function fmtBytes(n: number): string {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}

function ModeIcon({ mode }: { mode: string }) {
  if (mode === "mitm") {
    return (
      <span title="MITM" className="flex-shrink-0">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="#f6821f">
          <path d="M7 10V7a5 5 0 0 1 10 0v3h1a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h1Zm2 0h6V7a3 3 0 1 0-6 0v3Z" />
        </svg>
      </span>
    );
  }
  return (
    <span title="Splice" className="flex-shrink-0">
      <svg
        width="14"
        height="14"
        viewBox="0 0 24 24"
        fill="none"
        stroke="#a3a3a3"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M5 12h14" />
        <path d="m13 6 6 6-6 6" />
      </svg>
    </span>
  );
}
