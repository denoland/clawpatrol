// Settings-page credentials view: a grid of per-type cards (logo,
// display name, connected/total count) that expand a full-width
// details table immediately below the card's row when clicked.
//
// The card grid is rendered row-by-row so the details table can sit
// between the row of the active card and the next row — clicking a
// card on row 2 folds whatever is open and reopens the table below
// row 2. Sort is by pending-connection count descending so the
// types operators need to act on surface first.

import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { Integration, TailscaleNodeState } from "../lib/api";
import { clearCredential, oauthRevoke, tailscaleConnect, tailscaleDisconnect } from "../lib/api";
import {
  CREDENTIAL_CATEGORY_RANK,
  type CredentialCategory,
  credentialCategory,
  credentialTypeLabel,
} from "../lib/credentialLabels";
import { fmtExpiry } from "../lib/format";
import { CredentialSecretsModal } from "./CredentialSecretsModal";
import { IntegrationIcon } from "./Logos";
import { Tag } from "./Tag";

type Group = {
  type: string;
  label: string;
  category: CredentialCategory;
  items: Integration[];
  connected: number;
  total: number;
  pending: number;
};

function isConnected(i: Integration) {
  return i.connected || (i.tailscale_auth?.connected ?? false);
}

function isAuthable(i: Integration) {
  // A credential is "authable" if there's a connect surface for it
  // — OAuth, secret slots, or a Tailscale auth flow. Credentials
  // without any of these are declared-only (e.g. api-key-only types
  // wired through env or static HCL) and don't move toward
  // "connected" via dashboard actions.
  return Boolean(i.has_oauth || i.has_tailscale_auth || (i.slots && i.slots.length > 0));
}

function groupByType(list: Integration[]): Group[] {
  const groups = new Map<string, Group>();
  for (const i of list) {
    const key = i.type || "unknown";
    let g = groups.get(key);
    if (!g) {
      g = {
        type: key,
        label: credentialTypeLabel(key, key),
        category: credentialCategory(key),
        items: [],
        connected: 0,
        total: 0,
        pending: 0,
      };
      groups.set(key, g);
    }
    g.items.push(i);
    g.total++;
    if (isConnected(i)) g.connected++;
    else if (isAuthable(i)) g.pending++;
  }
  const out = [...groups.values()];
  // Order, by priority (most operator-relevant first):
  //   1. types with at least one pending credential beat types that
  //      are fully connected (or have nothing left to connect);
  //   2. within a tier, category rank — LLM > messaging > database
  //      > 3rd-party > generic-token > other;
  //   3. pending count descending, so the busiest type leads;
  //   4. label, alphabetical, for stable ties.
  out.sort((a, b) => {
    const aPending = a.pending > 0 ? 0 : 1;
    const bPending = b.pending > 0 ? 0 : 1;
    if (aPending !== bPending) return aPending - bPending;
    const aRank = CREDENTIAL_CATEGORY_RANK[a.category];
    const bRank = CREDENTIAL_CATEGORY_RANK[b.category];
    if (aRank !== bRank) return aRank - bRank;
    if (a.pending !== b.pending) return b.pending - a.pending;
    return a.label.localeCompare(b.label);
  });
  return out;
}

// sortDetailRows hoists pending-to-connect credentials to the top of
// the per-type details table and sorts within each bucket by
// updated_at descending — so the first non-pending row is the most
// recently connected credential.
function sortDetailRows(items: Integration[]): Integration[] {
  return [...items].sort((a, b) => {
    const aPending = !isConnected(a) && isAuthable(a) ? 0 : 1;
    const bPending = !isConnected(b) && isAuthable(b) ? 0 : 1;
    if (aPending !== bPending) return aPending - bPending;
    const aTs = a.updated_at ?? 0;
    const bTs = b.updated_at ?? 0;
    if (aTs !== bTs) return bTs - aTs;
    return a.name.localeCompare(b.name);
  });
}

// Approximate per-card minimum width. The grid is JS-driven (not
// CSS grid auto-placement) because we need to know which row the
// active card lives in so the details panel can be injected between
// rows. CSS `grid-column: 1 / -1` would auto-place at the next free
// row, not below a specific card's row.
const CARD_MIN_PX = 220;

function useColumnCount(ref: React.RefObject<HTMLDivElement>): number {
  const [cols, setCols] = useState(4);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const measure = () => {
      const w = el.clientWidth;
      // Match the gap baked into the row's flex layout (10px gap).
      const next = Math.max(1, Math.floor((w + 10) / (CARD_MIN_PX + 10)));
      setCols(next);
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [ref]);
  return cols;
}

export function CredentialsTypeGrid({
  list,
  onConnect,
  onRefresh,
}: {
  list: Integration[];
  onConnect: (id: string) => void;
  onRefresh: () => void;
}) {
  const [activeType, setActiveType] = useState<string | null>(null);
  const [editing, setEditing] = useState<Integration | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const cols = useColumnCount(containerRef);

  // Passthrough credentials inject nothing and have no connect flow —
  // there's no operator action to take on them, so they get no card
  // (and thus no type roll-up or details row) here.
  const groups = groupByType(list.filter((i) => !i.passthrough));

  // Drop the active type if it disappears from the list (e.g. a
  // reload removed every credential of that type).
  useEffect(() => {
    if (activeType && !groups.some((g) => g.type === activeType)) {
      setActiveType(null);
    }
  }, [activeType, groups]);

  function handleConnect(i: Integration) {
    if (i.has_tailscale_auth && i.tailscale_auth) {
      // Open the parked URL synchronously so popup blockers honor
      // the user gesture; the POST runs in parallel and refreshes
      // when tsnet reports "already joined". See IntegrationsCards
      // for the longer rationale.
      const parked = i.tailscale_auth.pending_url;
      if (parked) {
        window.open(parked, "_blank", "noopener,noreferrer");
      }
      tailscaleConnect(i.tailscale_auth.connect_url)
        .then((r) => {
          if (r.connected) {
            onRefresh();
            return;
          }
          if (!parked) {
            const url = r.auth_url || r.pending_url;
            if (url) {
              window.open(url, "_blank", "noopener,noreferrer");
            }
          }
        })
        .catch(() => {
          /* surfaced on the next refresh */
        });
      return;
    }
    if (i.has_oauth) {
      onConnect(i.id);
      return;
    }
    if (i.slots && i.slots.length > 0) {
      setEditing(i);
    }
  }

  function handleDisconnect(i: Integration) {
    const label = credentialTypeLabel(i.type, i.name);
    const what = i.has_oauth
      ? "revoke the OAuth token"
      : i.has_tailscale_auth
        ? "disconnect the Tailscale node"
        : "clear the stored secrets";
    if (
      !confirm(
        `Disconnect ${label} (${i.id})?\n\nThis will ${what}. You'll need to reconnect to use it again.`,
      )
    ) {
      return;
    }
    if (i.has_tailscale_auth && i.tailscale_auth) {
      tailscaleDisconnect(i.tailscale_auth.disconnect_url).then(onRefresh);
      return;
    }
    if (i.has_oauth) {
      oauthRevoke(i.id).then(onRefresh);
    } else {
      clearCredential(i.id).then(onRefresh);
    }
  }

  // Bucket groups into rows of `cols` cards. The details table is
  // emitted between rows immediately after the row the active card
  // belongs to, so a click on row 2's third card opens the table at
  // the same position regardless of what other rows look like.
  const rows: Group[][] = [];
  for (let i = 0; i < groups.length; i += cols) {
    rows.push(groups.slice(i, i + cols));
  }
  const activeIndex = activeType ? groups.findIndex((g) => g.type === activeType) : -1;
  const activeRow = activeIndex >= 0 ? Math.floor(activeIndex / cols) : -1;
  const activeGroup = activeIndex >= 0 ? groups[activeIndex] : null;

  return (
    <>
      <div ref={containerRef} className="flex flex-col gap-2.5">
        {rows.map((rowGroups, rowIdx) => (
          <div key={rowIdx} className="flex flex-col gap-2.5">
            <div
              className="grid gap-2.5"
              style={{ gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))` }}
            >
              {rowGroups.map((g) => (
                <TypeCard
                  key={g.type}
                  group={g}
                  active={g.type === activeType}
                  onClick={() => setActiveType((prev) => (prev === g.type ? null : g.type))}
                />
              ))}
            </div>
            {rowIdx === activeRow && activeGroup && (
              <DetailsPanel
                group={activeGroup}
                onClose={() => setActiveType(null)}
                onConnect={handleConnect}
                onDisconnect={handleDisconnect}
                onEdit={(i) => setEditing(i)}
              />
            )}
          </div>
        ))}
      </div>

      {editing && (
        <CredentialSecretsModal
          integration={editing}
          mode={isConnected(editing) ? "update" : "connect"}
          onClose={() => setEditing(null)}
          onSaved={onRefresh}
        />
      )}
    </>
  );
}

function TypeCard({
  group: g,
  active,
  onClick,
}: {
  group: Group;
  active: boolean;
  onClick: () => void;
}) {
  // Pick a representative item so the icon picker (which keys off
  // the credential id for legacy names like "claude" / "github")
  // still gets the right brand glyph when the type label alone
  // wouldn't disambiguate.
  const rep = g.items[0];
  const allConnected = g.connected === g.total && g.total > 0;
  const noneConnected = g.connected === 0;
  return (
    <button
      onClick={onClick}
      className={
        "group flex flex-col items-start gap-2 px-3 py-3 bg-canvas text-left transition-colors border-1.5 " +
        (active ? "border-text bg-navy-50" : "border-navy hover:bg-canvas-muted cursor-pointer")
      }
    >
      <div className="flex items-center gap-2 w-full">
        <IntegrationIcon id={rep.id} type={rep.type} className="w-[18px] h-[18px] shrink-0" />
        <span className="text-xs font-semibold text-text truncate" title={g.label}>
          {g.label}
        </span>
        <span
          className={
            "ml-auto w-[6px] h-[6px] rounded-full shrink-0 " +
            (allConnected ? "bg-success-500" : noneConnected ? "bg-text-subtle" : "bg-butter-500")
          }
        />
      </div>
      <div className="text-2xs tabular-nums text-text-muted">
        <span className="font-semibold text-text">{g.connected}</span>
        <span className="text-text-subtle">/{g.total}</span>
        <span className="ml-1">connected</span>
        {g.pending > 0 && <span className="ml-2 text-rust-700">{g.pending} pending</span>}
      </div>
    </button>
  );
}

function DetailsPanel({
  group,
  onClose,
  onConnect,
  onDisconnect,
  onEdit,
}: {
  group: Group;
  onClose: () => void;
  onConnect: (i: Integration) => void;
  onDisconnect: (i: Integration) => void;
  onEdit: (i: Integration) => void;
}) {
  // Config columns: the union of HCL attribute names across all
  // credentials of this type, in stable (sorted) order. Per the
  // bead: name / status / profile(s) / endpoint(s) come first, then
  // the per-field block contents fan out after.
  const configKeys = Array.from(
    new Set(group.items.flatMap((i) => Object.keys(i.config ?? {}))),
  ).sort();
  const rows = sortDetailRows(group.items);
  return (
    <div className="bg-canvas border-1.5 border-navy overflow-hidden">
      <div className="flex items-center justify-between gap-3 px-4 py-2.5 bg-navy-100 border-b border-navy">
        <div className="font-mono text-xs uppercase tracking-wider text-navy font-bold">
          {group.label} · {group.total} declared · {group.connected} connected
        </div>
        <button
          onClick={onClose}
          className="text-text text-sm leading-none px-1 cursor-pointer"
          title="fold"
        >
          ✕
        </button>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead className="font-mono text-2xs uppercase tracking-wider text-text-muted">
            <tr className="border-b border-canvas-dark">
              <th className="text-left font-semibold px-3 py-2">Name</th>
              <th className="text-left font-semibold px-3 py-2">Status</th>
              <th className="text-left font-semibold px-3 py-2">Profiles</th>
              <th className="text-left font-semibold px-3 py-2">Endpoints</th>
              {configKeys.map((k) => (
                <th key={k} className="text-left font-semibold px-3 py-2 whitespace-nowrap">
                  {k}
                </th>
              ))}
              <th className="text-right font-semibold px-3 py-2">Action</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((i) => (
              <DetailsRow
                key={i.id}
                integration={i}
                configKeys={configKeys}
                onConnect={() => onConnect(i)}
                onDisconnect={() => onDisconnect(i)}
                onEdit={() => onEdit(i)}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DetailsRow({
  integration: i,
  configKeys,
  onConnect,
  onDisconnect,
  onEdit,
}: {
  integration: Integration;
  configKeys: string[];
  onConnect: () => void;
  onDisconnect: () => void;
  onEdit: () => void;
}) {
  const connected = isConnected(i);
  const hasSlots = (i.slots?.length ?? 0) > 0;
  const canReset = i.has_tailscale_auth && (i.tailscale_auth?.has_state ?? false);
  const canConnect = !connected && (i.has_oauth || hasSlots || i.has_tailscale_auth);
  const canDisconnect = connected || canReset;
  const status = rowStatus(i, connected, hasSlots);
  const subtitle = rowSubtitle(i, connected);
  const profiles = i.profiles ?? [];
  const endpoints = i.endpoints ?? [];
  const cfg = i.config ?? {};
  return (
    <tr className="border-b border-canvas-dark last:border-b-0">
      <td className="px-3 py-2 align-top">
        <div className="font-mono text-text">{i.name}</div>
        {subtitle && <div className="text-2xs text-text-muted mt-0.5">{subtitle}</div>}
      </td>
      <td className="px-3 py-2 align-top">
        <span className="inline-flex items-center gap-1.5">
          <span
            className={
              "w-[6px] h-[6px] rounded-full " + (connected ? "bg-success-500" : "bg-text-subtle")
            }
          />
          <span className="text-text">{status}</span>
        </span>
      </td>
      <td className="px-3 py-2 align-top">
        <CellList items={profiles} />
      </td>
      <td className="px-3 py-2 align-top">
        <CellList items={endpoints} />
      </td>
      {configKeys.map((k) => (
        <td key={k} className="px-3 py-2 align-top font-mono text-text">
          {cfg[k] ?? <span className="text-text-subtle">—</span>}
        </td>
      ))}
      <td className="px-3 py-2 align-top whitespace-nowrap text-right">
        {canConnect && (
          <button
            onClick={onConnect}
            className="text-text hover:text-rust-700 underline underline-offset-2"
          >
            Connect
          </button>
        )}
        {connected && hasSlots && (
          <button
            onClick={onEdit}
            className="text-text hover:text-rust-700 underline underline-offset-2 ml-3"
          >
            Update
          </button>
        )}
        {canDisconnect && (
          <button
            onClick={onDisconnect}
            className="text-text-subtle hover:text-danger-500 underline underline-offset-2 ml-3"
          >
            Disconnect
          </button>
        )}
        {!canConnect && !canDisconnect && <span className="text-text-subtle">—</span>}
      </td>
    </tr>
  );
}

function CellList({ items }: { items: string[] }) {
  if (!items.length) return <span className="text-text-subtle">—</span>;
  return (
    <div className="flex flex-wrap gap-1 max-w-[18rem]">
      {items.map((n) => (
        <Tag key={n}>{n}</Tag>
      ))}
    </div>
  );
}

function rowStatus(i: Integration, connected: boolean, hasSlots: boolean): string {
  if (connected) {
    return i.expires_at ? "expires " + fmtExpiry(i.expires_at) : "connected";
  }
  if (i.has_tailscale_auth) {
    return tailscaleStatusLabel(i.tailscale_auth?.state);
  }
  if (i.has_oauth) return "click to connect";
  if (hasSlots) return "paste secret";
  return "api key only";
}

function rowSubtitle(i: Integration, connected: boolean): string {
  if (connected && i.display_name) return i.display_name;
  if (!connected && i.has_tailscale_auth) {
    const s = i.tailscale_auth?.state;
    if (s === "needs_login" || s === "needs_machine_auth") return "awaiting authentication";
    if (s === "in_use_other_user") return "in use by another user";
  }
  return "";
}

function tailscaleStatusLabel(state: TailscaleNodeState | undefined): string {
  switch (state) {
    case "needs_login":
    case "needs_machine_auth":
      return "awaiting authentication";
    case "starting":
      return "starting";
    case "stopped":
      return "stopped";
    case "in_use_other_user":
      return "error: in use by another user";
    case "running":
      return "connected";
    default:
      return "not connected";
  }
}
