import { useEffect, useState } from "react";
import {
  downloadActionFixture,
  getAction,
  type Agent,
  type EventRecord,
  type FacetSchema,
} from "../lib/api";
import { formatFacetValue, useFacets } from "../lib/facets";
import { fmtDateTime } from "../lib/format";
import { Button } from "./Button";
import { Main } from "./Main";
import { PageTitle, type Crumb } from "./PageTitle";
import { Tag } from "./Tag";

// isDenyAction matches every action label the dispatcher emits for a
// "this request was blocked" outcome — legacy `deny` / `hitl_deny`
// (pre-migration rows) and the post-migration `denied`.
function isDenyAction(action: string): boolean {
  return action === "deny" || action === "denied" || action === "hitl_deny";
}

// approverKindLabel humanises the plugin type the dispatcher records
// on the event. Unknown values fall through verbatim so the dashboard
// stays useful as plugin types evolve.
function approverKindLabel(type?: string): string {
  switch (type) {
    case "llm_approver":
      return "LLM";
    case "human_approver":
      return "human";
    case "dashboard":
      return "dashboard";
    default:
      return type || "approver";
  }
}

export function RequestDetailPage({ id, agents }: { id: string; agents: Agent[] }) {
  const [ev, setEv] = useState<EventRecord | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const { byFamily } = useFacets();

  useEffect(() => {
    getAction(id)
      .then(setEv)
      .catch((e) => setErr(e.message ?? "load failed"));
  }, [id]);

  if (err) {
    return (
      <Shell>
        <div className="text-sm text-danger-500">{err}</div>
      </Shell>
    );
  }
  if (!ev) {
    return (
      <Shell>
        <div className="text-xs text-text-subtle">Loading...</div>
      </Shell>
    );
  }

  const time = fmtDateTime(ev.ts);
  const status = ev.status || 0;
  const statusColor =
    status >= 500
      ? "text-danger-500"
      : status >= 400
        ? "text-rust-500"
        : status >= 300
          ? "text-butter-600"
          : status >= 200
            ? "text-success-600"
            : "text-text-muted";
  const schema = ev.family ? byFamily[ev.family] : undefined;
  // SQL-family records come from the postgres / clickhouse_native
  // conn-family plugins. They populate Facets with verb / tables /
  // functions / statement. The HTTP-shaped fields (status, body,
  // headers) are unused for these rows; render the SQL-specific
  // section instead of the generic facets list so Statement gets a
  // dedicated code block. The header collapses to host only — the
  // full breakdown lives in SQLDetail below.
  const isSQL = ev.family === "sql" || ev.mode === "pg" || ev.mode === "clickhouse_native";
  const header = isSQL
    ? {
        verb: ((ev.facets?.verb as string | undefined) ?? ev.method ?? "").toUpperCase(),
        body: "",
      }
    : headerFromFacets(ev, schema);
  const { verb, body } = header;
  const fullUrl = ev.host + (body && !body.startsWith("/") ? " " : "") + body;
  const facetFields = facetDetailRows(ev, schema);
  const hasReq = !!ev.req_body;
  const hasResp = !!ev.resp_body;
  const hasReqH = ev.req_headers && Object.keys(ev.req_headers).length > 0;
  const hasRespH = ev.resp_headers && Object.keys(ev.resp_headers).length > 0;
  const hasFacets = !isSQL && facetFields.length > 0;
  const hasSections = hasFacets || hasReq || hasResp || hasReqH || hasRespH;

  return (
    <Shell
      agentIP={ev.agent_ip}
      agentName={agents.find((a) => a.ip === ev.agent_ip)?.hostname}
      requestId={ev.id}
    >
      {/* header */}
      <div className="bg-canvas border-1.5 border-navy p-5 space-y-3">
        <div className="flex items-center gap-3 flex-wrap">
          <ModeIcon mode={ev.mode} />
          {verb && (
            <span className="font-mono text-xs uppercase font-semibold text-text-muted">
              {verb}
            </span>
          )}
          {!isSQL && (
            <span className={"text-sm tabular-nums font-semibold " + statusColor}>
              {status || "\u2014"}
            </span>
          )}
          <span className="text-sm text-text break-all font-mono" title={fullUrl}>
            {fullUrl}
          </span>
          <span className="ml-auto">
            <DownloadActionButton ev={ev} />
          </span>
        </div>
        <div className="flex items-center gap-4 text-xs text-text-muted flex-wrap">
          <span>{time}</span>
          <span>{ev.ms}ms</span>
          {ev.agent_ip && <span>{ev.agent_ip}</span>}
          {ev.in != null && ev.in > 0 && <span>in: {fmtBytes(ev.in)}</span>}
          {ev.out != null && ev.out > 0 && <span>out: {fmtBytes(ev.out)}</span>}
        </div>
        {(ev.action || ev.reason || ev.approver) && (
          <div className="flex items-center gap-2 text-xs flex-wrap">
            {ev.action && (
              <Tag tone={isDenyAction(ev.action) ? "danger" : "success"}>{ev.action}</Tag>
            )}
            {ev.approver && (
              <span className="text-text-muted">
                by <span className="text-text">{approverKindLabel(ev.approver_type)}</span>{" "}
                <code>{ev.approver}</code>
                {ev.approver_by && <span className="text-text-muted"> · {ev.approver_by}</span>}
              </span>
            )}
            {ev.reason && <span className="text-text-muted">{ev.reason}</span>}
          </div>
        )}
      </div>

      {/* sections */}
      {isSQL ? (
        <SQLDetail ev={ev} />
      ) : hasSections ? (
        <div className="bg-canvas border-1.5 border-navy divide-y divide-canvas-dark">
          {hasFacets && (
            <Section title="Request">
              <Facets rows={facetFields} />
            </Section>
          )}
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
        <div className="bg-canvas border-1.5 border-navy px-5 py-4 text-xs text-text-subtle">
          No request/response body captured
          {ev.mode === "splice" && " (spliced connection)"}
        </div>
      )}
    </Shell>
  );
}

// DownloadActionButton triggers a server-side reshape of this event
// into a `clawpatrol test` fixture and saves it as a .json file. The
// runner reads files in this exact format — drop the download into a
// fixtures/ directory and `clawpatrol test config.hcl fixtures/` will
// replay it against a candidate policy. See site/doc/clawpatrol-test.md.
function DownloadActionButton({ ev }: { ev: EventRecord }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (!ev.id) return null;
  if (!ev.endpoint) return null;
  if (ev.action === "in_flight") return null;
  return (
    <Button
      variant="outline"
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        setErr(null);
        try {
          const blob = await downloadActionFixture(ev.id!);
          const href = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = href;
          a.download = `${ev.id}.json`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(href);
        } catch (e) {
          setErr((e as Error).message || "download failed");
        } finally {
          setBusy(false);
        }
      }}
      title={err ?? "Download as a Claw Patrol test fixture"}
    >
      {busy ? "Downloading…" : "Download action"}
    </Button>
  );
}

// --- SQL detail ---

// SQLDetail renders the postgres / clickhouse_native per-query view.
// Statement is the deliverable (operators want the raw SQL); verb /
// tables / functions are the parser's rule-targeting facets, surfaced
// here so it's obvious why a given rule fired or didn't. Reads from
// ev.facets (populated by the sql facet's Report hook) since the
// generic facet pipeline replaced the legacy direct fields.
function SQLDetail({ ev }: { ev: EventRecord }) {
  const f = ev.facets ?? {};
  const verb = (typeof f.verb === "string" ? f.verb : (ev.method ?? "")).toUpperCase();
  const tables = Array.isArray(f.tables) ? (f.tables as string[]) : [];
  const functions = Array.isArray(f.functions) ? (f.functions as string[]) : [];
  const statement = typeof f.statement === "string" ? f.statement : "";
  const facets: Array<{ label: string; value: string }> = [];
  if (verb) facets.push({ label: "Verb", value: verb });
  if (tables.length > 0) facets.push({ label: "Tables", value: tables.join(", ") });
  if (functions.length > 0) {
    facets.push({
      label: "Functions",
      value: functions.map((s) => s.toUpperCase()).join(", "),
    });
  }
  return (
    <div className="bg-canvas border-1.5 border-navy divide-y divide-canvas-dark">
      {facets.length > 0 && (
        <Section title="Details">
          <div className="px-4 py-3 grid grid-cols-[100px_1fr] gap-y-1.5 gap-x-3 text-xs">
            {facets.map((f) => (
              <div key={f.label} className="contents">
                <div className="font-mono text-2xs uppercase tracking-wider text-text-subtle pt-0.5">
                  {f.label}
                </div>
                <div className="text-text font-mono break-all">{f.value}</div>
              </div>
            ))}
          </div>
        </Section>
      )}
      <Section title="Statement">
        {statement ? (
          <pre className="overflow-auto whitespace-pre-wrap break-all px-4 py-3 font-mono text-xs leading-relaxed text-text">
            {statement}
          </pre>
        ) : (
          <div className="px-4 py-3 text-xs text-text-subtle">(no parsed statement)</div>
        )}
      </Section>
    </div>
  );
}

// --- layout ---

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
  const trail: Crumb[] = [];
  if (agentIP) {
    trail.push({ label: "Devices", href: "#/devices" });
    trail.push({
      label: agentName || agentIP,
      href: `#/device/${encodeURIComponent(agentIP)}`,
    });
  }
  if (requestId) {
    trail.push({
      label: (
        <span className="font-mono" title={requestId}>
          {requestId.split("-").pop()}
        </span>
      ),
    });
  }
  return (
    <Main>
      <PageTitle trail={trail} />
      {children}
    </Main>
  );
}

// headerFromFacets picks the verb + body strings for the event
// header. With a known facet schema, the leading column is
// method/verb and the trailing body collapses every other report
// field (status excepted, since it has its own coloured slot). New
// protocol facets render correctly without touching this file.
function headerFromFacets(
  ev: EventRecord,
  schema: FacetSchema | undefined,
): { verb: string; body: string } {
  const facets = ev.facets ?? {};
  if (schema && Object.keys(facets).length > 0) {
    const leadName =
      schema.report_fields.find((f) => f.name === "method")?.name ??
      schema.report_fields.find((f) => f.name === "verb")?.name ??
      "";
    const verbField = leadName ? schema.report_fields.find((f) => f.name === leadName) : undefined;
    const verb = verbField ? formatFacetValue(verbField.kind, facets[leadName]) : "";
    const bodyParts: string[] = [];
    for (const f of schema.report_fields) {
      if (f.name === leadName || f.name === "status") continue;
      const v = formatFacetValue(f.kind, facets[f.name]);
      if (v) bodyParts.push(v);
    }
    return { verb, body: bodyParts.join(" · ") };
  }
  return { verb: ev.method ?? "", body: ev.path ?? "" };
}

// facetDetailRows returns the per-family fields shown in the
// "facets" section under the request header. Renders every
// report-field the schema declares for which the event carries a
// non-empty value; unknown families fall back to the raw facets
// object so the operator still sees what was captured.
function facetDetailRows(
  ev: EventRecord,
  schema: FacetSchema | undefined,
): Array<{ name: string; label: string; value: string }> {
  const facets = ev.facets;
  if (!facets || Object.keys(facets).length === 0) return [];
  if (!schema) {
    return Object.entries(facets).map(([k, v]) => ({
      name: k,
      label: k,
      value: typeof v === "string" ? v : JSON.stringify(v),
    }));
  }
  const out: Array<{ name: string; label: string; value: string }> = [];
  for (const f of schema.report_fields) {
    const v = formatFacetValue(f.kind, facets[f.name]);
    if (v) out.push({ name: f.name, label: f.label || f.name, value: v });
  }
  return out;
}

// Facets renders the per-family report payload using the same
// monospace key:value layout as the Request/Response headers list,
// so the detail page reads consistently regardless of which facet
// owns the row. No masking: the facets payload is policy metadata,
// not secret material (credentials live in headers).
function Facets({ rows }: { rows: Array<{ name: string; label: string; value: string }> }) {
  return (
    <pre className="overflow-auto whitespace-pre-wrap break-all px-4 py-3 font-mono text-xs leading-relaxed">
      {rows.map((r) => (
        <div key={r.name}>
          <span className="font-semibold text-text">{r.label}</span>
          <span className="text-text-subtle">: </span>
          <span className="text-text-muted">{r.value}</span>
        </div>
      ))}
    </pre>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <details open>
      <summary className="cursor-pointer px-4 py-2.5 text-xs font-mono uppercase tracking-wider font-bold text-navy bg-navy-100 border-b border-navy hover:text-text select-none">
        {title}
      </summary>
      <div>{children}</div>
    </details>
  );
}

// --- headers ---

const SENSITIVE = /auth|token|secret|key|password|cookie/i;

function Headers({ obj }: { obj: Record<string, string> }) {
  return (
    <pre className="overflow-auto whitespace-pre-wrap break-all px-4 py-3 font-mono text-xs leading-relaxed">
      {Object.entries(obj).map(([k, v]) => (
        <div key={k}>
          <span className="font-semibold text-text">{k}</span>
          <span className="text-text-subtle">: </span>
          {SENSITIVE.test(k) ? (
            <span className="text-text-subtle">{"*".repeat(Math.min(v.length, 24))}</span>
          ) : (
            <span className="text-text-muted">{v}</span>
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
  if (!text) return <div className="px-4 py-3 text-xs text-text-subtle">(empty)</div>;
  const result = tryParseJSON(text);
  if (result) {
    return (
      <div className="overflow-auto px-4 py-3 font-mono text-xs leading-relaxed">
        <JsonNode value={result.parsed} />
        {result.truncated && <div className="mt-2 text-2xs text-text-subtle">(truncated)</div>}
      </div>
    );
  }
  const sse = parseSSE(text);
  if (sse) {
    return (
      <div className="overflow-auto px-4 py-3 font-mono text-xs leading-relaxed space-y-3">
        {sse.map((e, i) => {
          const dataJson = tryParseJSON(e.data);
          return (
            <div key={i}>
              {e.type && (
                <div className="font-mono text-2xs uppercase tracking-wider text-text-subtle mb-1">
                  event:{" "}
                  <span className="normal-case tracking-normal text-text-muted">{e.type}</span>
                </div>
              )}
              {dataJson ? (
                <>
                  <JsonNode value={dataJson.parsed} />
                  {dataJson.truncated && (
                    <div className="mt-1 text-2xs text-text-subtle">(truncated)</div>
                  )}
                </>
              ) : (
                <pre className="whitespace-pre-wrap break-all text-text-muted">{e.data}</pre>
              )}
            </div>
          );
        })}
      </div>
    );
  }
  return (
    <pre className="overflow-auto whitespace-pre-wrap break-all px-4 py-3 font-mono text-xs text-text-muted">
      {text}
    </pre>
  );
}

// --- JSON tree (ported from unclaw) ---

const LONG_STRING = 120;

function JsonNode({ value }: { value: unknown }) {
  if (value === null) {
    return <span className="font-semibold text-text-subtle">null</span>;
  }
  if (typeof value === "boolean") {
    return <span className="font-semibold text-rust-700">{String(value)}</span>;
  }
  if (typeof value === "number") {
    return <span className="text-navy-500">{String(value)}</span>;
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
            <span className="text-danger-700">{JSON.stringify(k)}</span>
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
    return <span className="text-success-700">{raw}</span>;
  }
  if (!expanded) {
    return (
      <span>
        <span className="text-success-700">{raw.slice(0, LONG_STRING)}</span>
        <button onClick={() => setExpanded(true)} className="ml-1 text-navy-500 hover:underline">
          +{raw.length - LONG_STRING} more
        </button>
      </span>
    );
  }
  const inner = raw.slice(1, -1);
  const lines = inner.split("\\n");
  return (
    <span className="text-success-700">
      {'"'}
      {lines.map((line, i) => (
        <span key={i}>
          {line}
          {i < lines.length - 1 && (
            <>
              <span className="text-text-subtle">\n</span>
              <br />
            </>
          )}
        </span>
      ))}
      {'"'}
      <button onClick={() => setExpanded(false)} className="ml-1 text-navy-500 hover:underline">
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
      <button onClick={() => setOpen(true)} className="text-text cursor-pointer">
        {bracket[0]} <span className="text-navy-500">{count} items</span> {bracket[1]}
      </button>
    );
  }
  return (
    <span>
      <button onClick={() => setOpen(false)} className="hover:text-text-subtle">
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
      <span title="MITM" className="shrink-0 text-rust-400">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
          <path d="M7 10V7a5 5 0 0 1 10 0v3h1a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h1Zm2 0h6V7a3 3 0 1 0-6 0v3Z" />
        </svg>
      </span>
    );
  }
  return (
    <span title="Splice" className="shrink-0 text-text-subtle">
      <svg
        width="14"
        height="14"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
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
