import type { ProfileEndpoint } from "../lib/api";

// EndpointFlowMap renders a single endpoint's request-path flow as a
// hand-rolled SVG block: endpoint → optional tunnel chain → per-rule
// fan-out → credential convergence. The flow runs top-to-bottom so
// rule and credential fan-outs spread horizontally — endpoints with
// many rules don't blow up the page height anymore. Hand-rolled
// because the layout is row-grid (fixed top-to-bottom ordering, no
// force-direction to solve) — a graph library would weigh more than
// the file below and force us to re-skin every node anyway.
//
// Layout:
//
//   [endpoint]
//       ↓
//   [tunnel]*
//       ↓
//   [rule] [rule] [rule] …
//       ↓     ↓     ↓
//   [credential]*
//
// Rows are fixed-height; columns = max(rules, credentials, 1) so the
// rule and credential rows stay aligned. Endpoint + tunnels are
// horizontally centered against that width. Edges are drawn as
// orthogonal SVG paths from bottom-of-source to top-of-target so the
// operator can trace which rules route to which credential,
// including the multi-credential-with-disambiguator case where each
// credential node carries its dispatch discriminator (key=value
// pairs the dispatcher matches on to pick that credential over its
// siblings).

const COL_WIDTH = 160;
const NODE_WIDTH = 140;
const ROW_HEIGHT = 92;
const NODE_H_SHORT = 56;
const NODE_H_TALL = 64;
const SVG_PAD_X = 12;
const SVG_PAD_Y = 8;

type NodePos = { x: number; y: number; w: number; h: number };

export function EndpointFlowMap({ endpoint }: { endpoint: ProfileEndpoint }) {
  const tunnels = endpoint.tunnel_chain ?? [];
  const rules = endpoint.rules ?? [];
  const creds = endpoint.credentials ?? [];

  // Render a placeholder credential when the endpoint has no
  // declared bindings (rare — usually a misconfig) so the rules
  // row still has somewhere to terminate visually.
  const credColumn =
    creds.length > 0 ? creds : [{ credential: "(no credential)", disambiguators: undefined }];
  const ruleColumn = rules.length > 0 ? rules : null;

  const colCount = Math.max(ruleColumn?.length ?? 0, credColumn.length, 1);
  const hasRuleRow = ruleColumn !== null;
  const rowCount = 1 + tunnels.length + (hasRuleRow ? 1 : 0) + 1;

  const innerWidth = COL_WIDTH * colCount + 20;
  const innerHeight = ROW_HEIGHT * rowCount;

  const totalWidth = innerWidth + SVG_PAD_X * 2;
  const totalHeight = innerHeight + SVG_PAD_Y * 2;

  // Center a row of `count` nodes horizontally across the inner width.
  const nodeX = (i: number, count: number) => {
    const rowSpan = NODE_WIDTH + (count - 1) * COL_WIDTH;
    const startX = SVG_PAD_X + (innerWidth - rowSpan) / 2;
    return startX + i * COL_WIDTH;
  };

  // Top-of-cell Y for a given row index, with the node vertically
  // centered against its row by passing the node's own height in.
  const rowY = (rowIdx: number, nodeH: number) =>
    SVG_PAD_Y + rowIdx * ROW_HEIGHT + (ROW_HEIGHT - nodeH) / 2;

  let row = 0;
  const endpointRow = row++;
  const tunnelRows = tunnels.map(() => row++);
  const ruleRow = hasRuleRow ? row++ : -1;
  const credRow = row++;

  const endpointNode: NodePos = {
    x: nodeX(0, 1),
    y: rowY(endpointRow, NODE_H_SHORT),
    w: NODE_WIDTH,
    h: NODE_H_SHORT,
  };
  const tunnelNodes: NodePos[] = tunnels.map((_, i) => ({
    x: nodeX(0, 1),
    y: rowY(tunnelRows[i], NODE_H_SHORT),
    w: NODE_WIDTH,
    h: NODE_H_SHORT,
  }));
  const ruleNodes: NodePos[] = (ruleColumn ?? []).map((_, i) => ({
    x: nodeX(i, ruleColumn?.length ?? 1),
    y: rowY(ruleRow, NODE_H_TALL),
    w: NODE_WIDTH,
    h: NODE_H_TALL,
  }));
  const credNodes: NodePos[] = credColumn.map((_, i) => ({
    x: nodeX(i, credColumn.length),
    y: rowY(credRow, NODE_H_TALL),
    w: NODE_WIDTH,
    h: NODE_H_TALL,
  }));

  // Edges:
  //   endpoint -> tunnels[0] (or fan-out)
  //   tunnel[i] -> tunnel[i+1]
  //   last tunnel (or endpoint) -> each rule
  //   each rule -> credential it routes to (or all when unconstrained)
  const edges: Array<{ from: NodePos; to: NodePos; emphasis?: boolean }> = [];
  const fanOutSource = tunnelNodes.length > 0 ? tunnelNodes[tunnelNodes.length - 1] : endpointNode;

  if (tunnelNodes.length > 0) {
    edges.push({ from: endpointNode, to: tunnelNodes[0] });
    for (let i = 0; i < tunnelNodes.length - 1; i++) {
      edges.push({ from: tunnelNodes[i], to: tunnelNodes[i + 1] });
    }
  }

  if (ruleColumn && ruleColumn.length > 0) {
    ruleColumn.forEach((_, i) => {
      edges.push({ from: fanOutSource, to: ruleNodes[i] });
    });
    // rules -> credentials. A rule with rule.credential = "X" routes
    // strictly to credential X. A rule without that filter could
    // resolve to any of the endpoint's bindings (the dispatcher then
    // picks via disambiguators), so we draw all-edges to keep the
    // operator's mental model intact.
    ruleColumn.forEach((r, i) => {
      const ruleNode = ruleNodes[i];
      const allow = r.verdict !== "deny";
      if (!allow) return; // deny rules don't terminate at a credential
      if (r.credential) {
        const idx = credColumn.findIndex((c) => c.credential === r.credential);
        if (idx >= 0) edges.push({ from: ruleNode, to: credNodes[idx], emphasis: true });
      } else {
        credColumn.forEach((_, ci) => edges.push({ from: ruleNode, to: credNodes[ci] }));
      }
    });
  } else {
    // No rules — drive the flow straight from the fan-out source to
    // every credential so the diagram still terminates somewhere.
    credColumn.forEach((_, i) => edges.push({ from: fanOutSource, to: credNodes[i] }));
  }

  return (
    <div className="bg-canvas border-1.5 border-navy">
      <div className="px-3 py-2 bg-navy-100 border-b border-navy flex items-baseline gap-2 flex-wrap">
        <div className="font-mono text-xs uppercase tracking-wider text-navy font-bold">
          {endpoint.name}
        </div>
        <span className="font-mono text-2xs uppercase tracking-wider text-navy/70">
          {endpoint.family}
        </span>
        {endpoint.hosts && endpoint.hosts.length > 0 && (
          <span className="text-2xs text-navy/70 font-mono truncate">
            {endpoint.hosts.join(", ")}
          </span>
        )}
      </div>
      <div className="overflow-x-auto">
        <svg
          width={totalWidth}
          height={totalHeight}
          viewBox={`0 0 ${totalWidth} ${totalHeight}`}
          className="block"
          role="img"
          aria-label={`flow map for endpoint ${endpoint.name}`}
        >
          {edges.map((e, i) => (
            <Edge key={i} from={e.from} to={e.to} emphasis={e.emphasis} />
          ))}
          <Node
            pos={endpointNode}
            kind="endpoint"
            title={endpoint.name}
            subtitle={endpoint.family}
          />
          {tunnels.map((t, i) => (
            <Node
              key={t.name + ":" + i}
              pos={tunnelNodes[i]}
              kind="tunnel"
              title={t.name}
              subtitle={[t.sharing && `share=${t.sharing}`, t.credential && `auth=${t.credential}`]
                .filter(Boolean)
                .join(" · ")}
            />
          ))}
          {(ruleColumn ?? []).map((r, i) => (
            <Node
              key={r.name + ":" + i}
              pos={ruleNodes[i]}
              kind="rule"
              title={r.name}
              subtitle={ruleSubtitle(r)}
              dimmed={r.disabled}
            />
          ))}
          {credColumn.map((c, i) => (
            <Node
              key={c.credential + ":" + i}
              pos={credNodes[i]}
              kind="credential"
              title={c.credential}
              subtitle={disambiguatorLabel(c.disambiguators)}
            />
          ))}
        </svg>
      </div>
    </div>
  );
}

function ruleSubtitle(r: NonNullable<ProfileEndpoint["rules"]>[number]): string {
  const parts: string[] = [];
  if (r.verdict) parts.push(r.verdict);
  if (typeof r.priority === "number" && r.priority !== 0) parts.push(`p=${r.priority}`);
  if (r.credential) parts.push(`cred=${r.credential}`);
  if (r.disabled) parts.push("disabled");
  return parts.join(" · ");
}

// disambiguatorLabel renders the operator-set discriminator
// key=value pairs that route a request to this credential over its
// siblings on the same endpoint. Empty for catch-all bindings; the
// detail page surfaces these on the node itself rather than in a
// tooltip per the cl-l6zv acceptance criteria ("not buried in a
// tooltip"). Trims surrounding HCL quotes so "user=\"ro_app\""
// renders as `user=ro_app`.
function disambiguatorLabel(d: Record<string, string> | undefined): string {
  if (!d) return "";
  const pairs = Object.entries(d).map(([k, v]) => `${k}=${stripQuotes(v)}`);
  return pairs.join(" · ");
}

function stripQuotes(s: string): string {
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1);
  return s;
}

function Node({
  pos,
  kind,
  title,
  subtitle,
  dimmed,
}: {
  pos: NodePos;
  kind: "endpoint" | "tunnel" | "rule" | "credential";
  title: string;
  subtitle: string;
  dimmed?: boolean;
}) {
  const fill =
    kind === "endpoint"
      ? "#fff7e6"
      : kind === "tunnel"
        ? "#e6f0ff"
        : kind === "rule"
          ? "#f1f4f7"
          : "#eaf5ec";
  return (
    <g opacity={dimmed ? 0.5 : 1}>
      <rect
        x={pos.x}
        y={pos.y}
        width={pos.w}
        height={pos.h}
        rx={2}
        fill={fill}
        stroke="#11203a"
        strokeWidth={1.5}
      />
      <text
        x={pos.x + 8}
        y={pos.y + 16}
        className="fill-navy"
        fontSize={9}
        fontFamily="ui-monospace, SFMono-Regular, monospace"
        letterSpacing="0.05em"
      >
        {kind.toUpperCase()}
      </text>
      <text
        x={pos.x + 8}
        y={pos.y + 32}
        className="fill-text"
        fontSize={12}
        fontWeight={600}
        fontFamily="ui-monospace, SFMono-Regular, monospace"
      >
        {truncate(title, 18)}
      </text>
      {subtitle && (
        <text
          x={pos.x + 8}
          y={pos.y + (pos.h - 8)}
          className="fill-text-muted"
          fontSize={10}
          fontFamily="ui-monospace, SFMono-Regular, monospace"
        >
          {truncate(subtitle, 22)}
        </text>
      )}
    </g>
  );
}

function Edge({ from, to, emphasis }: { from: NodePos; to: NodePos; emphasis?: boolean }) {
  const x1 = from.x + from.w / 2;
  const y1 = from.y + from.h;
  const x2 = to.x + to.w / 2;
  const y2 = to.y;
  const midY = (y1 + y2) / 2;
  const d = `M ${x1} ${y1} C ${x1} ${midY}, ${x2} ${midY}, ${x2} ${y2}`;
  return (
    <path
      d={d}
      fill="none"
      stroke={emphasis ? "#11203a" : "#9aa6b5"}
      strokeWidth={emphasis ? 1.75 : 1.25}
    />
  );
}

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + "…";
}
