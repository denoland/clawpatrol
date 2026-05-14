import * as React from "react";
import { useEffect, useState } from "react";
import type { Integration } from "../lib/api";
import { clearCredential, oauthRevoke, tailscaleConnect, tailscaleDisconnect } from "../lib/api";
import { credentialTypeLabel } from "../lib/credentialLabels";
import { fmtExpiry } from "../lib/format";
import { CredentialSecretsModal } from "./CredentialSecretsModal";
import { IntegrationIcon } from "./Logos";
import { Modal } from "./Modal";

// Card header format: `<plugin display name> · <credential bare name>`.
// The bare name (the operator's HCL block name) is always present so
// two same-type cards can be told apart at a glance, and so the
// subtitle slot below the header is free for per-type contextual
// information (OAuth identity, "Not connected", etc.) instead of
// repeating the block name.

// Cap on visible cards before the overflow button appears. The N-th
// slot is replaced by "+ K more" so the row width stays predictable
// — 3 cards + 1 overflow button keeps the device-page row tidy.
const VISIBLE_CAP = 4;

export function IntegrationsCards({
  list,
  showAll,
  onConnect,
  onRefresh,
  pendingConnect,
  onConsumePendingConnect,
}: {
  list: Integration[];
  // When true, render every card in the grid (no overflow button,
  // no "+ K more" modal). Used by the Settings page where the
  // credentials row IS the page and there's space for the full list.
  showAll?: boolean;
  onConnect: (id: string) => void;
  onRefresh: () => void;
  // A credential id the parent wants the connect flow auto-opened for.
  // Set by the agents-table click-through (?connect=<id> on the
  // device-page URL); cleared via onConsumePendingConnect once we've
  // acted on it so a reload doesn't reopen the modal.
  pendingConnect?: string;
  onConsumePendingConnect?: () => void;
}) {
  const [editing, setEditing] = useState<Integration | null>(null);
  const [allOpen, setAllOpen] = useState(false);

  // Sort: connected first, then unconnected, then disabled (no auth
  // path) — preserves declaration order within each bucket. Only used
  // by the device-page row (compact + overflow). The Settings page
  // (showAll) groups by plugin type instead — see groupedByType below.
  const sorted = [...list].sort((a, b) => {
    const score = (i: Integration) => {
      if (i.connected || i.tailscale_auth?.connected) return 0;
      if (i.has_oauth || i.has_tailscale_auth || (i.slots && i.slots.length > 0)) return 1;
      return 2;
    };
    return score(a) - score(b);
  });

  const overflow = !showAll && sorted.length > VISIBLE_CAP;
  const visible = overflow ? sorted.slice(0, VISIBLE_CAP - 1) : sorted;
  const hiddenCount = sorted.length - visible.length;

  // Settings-page grouping: split by connection state first
  // (Connected / Not Configured) and then cluster by plugin type
  // within each state. The two state sections stack vertically; the
  // per-type boxes inside each section flow horizontally and wrap on
  // overflow so a long credential catalog scans like a grid of
  // labelled clusters rather than a vertical ladder.
  const groupedByStatus = showAll ? groupByStatusThenType(list) : null;

  function handleConnect(i: Integration) {
    if (i.has_tailscale_auth && i.tailscale_auth) {
      // The parked URL from /api/state is the same one /api/tailscale/connect
      // would return — tsnet only mints a new one when the previous is
      // consumed/expires. Open it *synchronously* inside the click handler
      // so popup blockers treat it as user-initiated; calling window.open
      // from inside a fetch.then() resolution is silently blocked by
      // every modern browser, which is the "click closes the modal as a
      // no-op" failure surfaced on PR #284.
      const parked = i.tailscale_auth.pending_url;
      if (parked) {
        window.open(parked, "_blank", "noopener,noreferrer");
      }
      // Still POST so the "already joined" path flips the card to
      // "connected" without waiting for the next /api/state poll, and
      // so the operator sees a fresh URL on the next click if tsnet
      // has emitted one since the last list refresh.
      tailscaleConnect(i.tailscale_auth.connect_url)
        .then((r) => {
          if (r.connected) {
            onRefresh();
            return;
          }
          // Fallback for the no-parked-URL case: tsnet may have parked
          // a URL between /api/state and this POST. Open it now even
          // though we're outside the click — better a popup-blocker
          // warning than another silent no-op.
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

  // Auto-open the connect flow when navigated to via ?connect=<id>.
  // Runs once per pendingConnect value; consuming the prop signals the
  // parent to drop the query param from the URL so a reload doesn't
  // reopen the same modal.
  useEffect(() => {
    if (!pendingConnect) return;
    const target = list.find((i) => i.id === pendingConnect);
    if (!target) return;
    handleConnect(target);
    onConsumePendingConnect?.();
    // handleConnect / onConsume are stable per render; we deliberately
    // re-run only when pendingConnect changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingConnect]);

  function disconnect(i: Integration) {
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

  return (
    <>
      {groupedByStatus ? (
        <div className="space-y-6">
          {groupedByStatus.map((section) => (
            <section key={section.status} className="space-y-2.5">
              <h3 className="text-2xs uppercase tracking-[.12em] text-text-muted font-bold flex items-baseline gap-1.5">
                <span>{section.label}</span>
                <span className="text-text-subtle font-normal">— {section.total}</span>
              </h3>
              <div className="flex flex-wrap gap-x-6 gap-y-4">
                {section.types.map((g) => (
                  <div key={g.type} className="space-y-1.5">
                    <div className="text-2xs uppercase tracking-[.12em] text-text-subtle flex items-baseline gap-1.5">
                      <span>{g.label}</span>
                      <span>— {g.items.length}</span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {g.items.map((i) => (
                        <div key={i.id} className="w-44">
                          <Card
                            integration={i}
                            onConnect={() => handleConnect(i)}
                            onDisconnect={() => disconnect(i)}
                          />
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2.5">
          {visible.map((i) => (
            <Card
              key={i.id}
              integration={i}
              onConnect={() => handleConnect(i)}
              onDisconnect={() => disconnect(i)}
            />
          ))}
          {overflow && (
            <button
              onClick={() => setAllOpen(true)}
              className="flex items-center justify-center px-3 py-2.5 bg-canvas-light border-2 border-dashed border-navy text-xs text-text-muted hover:bg-navy-50 hover:text-text transition-colors"
            >
              + {hiddenCount} more
            </button>
          )}
        </div>
      )}

      {allOpen && (
        <AllIntegrationsModal
          list={sorted}
          onClose={() => setAllOpen(false)}
          onConnect={(i) => {
            setAllOpen(false);
            handleConnect(i);
          }}
          onDisconnect={disconnect}
        />
      )}

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

function isConnected(i: Integration) {
  return i.connected || (i.tailscale_auth?.connected ?? false);
}

type CredentialGroup = {
  type: string;
  label: string;
  items: Integration[];
};

type StatusSection = {
  status: "connected" | "unconfigured";
  label: string;
  total: number;
  types: CredentialGroup[];
};

// groupByStatusThenType splits the credential list into Connected /
// Not Configured sections and clusters each section by plugin type.
// Empty sections are dropped so a fully-connected (or fully-empty)
// catalog doesn't render a stub heading. The unconfigured bucket
// also catches credentials with no auth path at all — from the
// operator's point of view those are equally "not yet usable".
function groupByStatusThenType(list: Integration[]): StatusSection[] {
  const connected: Integration[] = [];
  const unconfigured: Integration[] = [];
  for (const i of list) {
    if (isConnected(i)) connected.push(i);
    else unconfigured.push(i);
  }
  const sections: StatusSection[] = [];
  if (connected.length > 0) {
    sections.push({
      status: "connected",
      label: "Connected",
      total: connected.length,
      types: groupByType(connected),
    });
  }
  if (unconfigured.length > 0) {
    sections.push({
      status: "unconfigured",
      label: "Not configured",
      total: unconfigured.length,
      types: groupByType(unconfigured),
    });
  }
  return sections;
}

function groupByType(list: Integration[]): CredentialGroup[] {
  const buckets = new Map<string, Integration[]>();
  for (const i of list) {
    const arr = buckets.get(i.type);
    if (arr) arr.push(i);
    else buckets.set(i.type, [i]);
  }
  return Array.from(buckets.entries())
    .map(([type, items]) => ({
      type,
      label: credentialTypeLabel(type, type),
      items: [...items].sort((a, b) => a.name.localeCompare(b.name)),
    }))
    .sort((a, b) => a.label.localeCompare(b.label));
}

// OwnerAvatar renders the OAuth user's PFP (e.g. github avatar) with
// the provider icon as fallback when the image 404s or the host
// blocks hotlinking. Failure flips to icon via state, not just an
// onError swap, so a busted CDN doesn't leave a broken-image glyph.
function OwnerAvatar({
  src,
  fallbackId,
  fallbackType,
}: {
  src: string;
  fallbackId: string;
  fallbackType: string;
}) {
  const [broken, setBroken] = React.useState(false);
  if (broken) {
    return (
      <IntegrationIcon id={fallbackId} type={fallbackType} className="w-[16px] h-[16px] shrink-0" />
    );
  }
  return (
    <img
      src={src}
      alt=""
      onError={() => setBroken(true)}
      className="w-[16px] h-[16px] shrink-0 rounded-full object-cover"
    />
  );
}

function Card({
  integration: i,
  onConnect,
  onDisconnect,
}: {
  integration: Integration;
  onConnect: () => void;
  onDisconnect: () => void;
}) {
  const connected = isConnected(i);
  const hasSlots = (i.slots?.length ?? 0) > 0;
  const clickable = i.has_oauth || hasSlots || (i.has_tailscale_auth && !connected);
  const status = connected
    ? i.expires_at
      ? "expires " + fmtExpiry(i.expires_at)
      : "connected"
    : i.has_oauth || i.has_tailscale_auth
      ? "click to connect"
      : hasSlots
        ? "paste secret"
        : "api key only";
  // Plugin display name (e.g. "GitHub", "Postgres"). Falls back to the
  // raw HCL type key for unrecognised plugins rather than the bare
  // credential name, which would produce `<name> · <name>` titles.
  const label = credentialTypeLabel(i.type, i.type);
  // Title is always `<displayName> · <name>` regardless of how many
  // creds of this type are declared. The OAuth identity that used to
  // suffix the title moves to the subtitle below.
  const heading = `${label} · ${i.name}`;
  const subtitle = contextualSubtitle(i, connected, hasSlots);
  const title = [heading, `credential: ${i.id}`, `type: ${i.type}`, status].join("\n");
  return (
    <button
      disabled={!clickable && !connected}
      onClick={() => clickable && onConnect()}
      className={
        "group relative w-full flex flex-col items-start gap-2 px-3 py-2.5 bg-canvas-light border-2 border-navy text-left transition-colors " +
        (clickable ? "cursor-pointer hover:bg-navy-50" : "cursor-default")
      }
    >
      <div className="flex items-center gap-2 w-full">
        {connected && i.avatar_url ? (
          <OwnerAvatar src={i.avatar_url} fallbackId={i.id} fallbackType={i.type} />
        ) : (
          <IntegrationIcon id={i.id} type={i.type} className="w-[16px] h-[16px] shrink-0" />
        )}
        <span className="text-xs font-semibold text-text truncate" title={title}>
          {heading}
        </span>
        <span className="ml-auto flex items-center gap-1.5 shrink-0">
          {connected && (
            <span
              onClick={(e) => {
                e.stopPropagation();
                onDisconnect();
              }}
              className="opacity-0 group-hover:opacity-100 text-xs leading-none text-text-subtle hover:text-danger-500 transition-opacity cursor-pointer"
              title="disconnect"
            >
              ✕
            </span>
          )}
          <span
            className={
              "w-[6px] h-[6px] rounded-full " + (connected ? "bg-success-500" : "bg-text-subtle")
            }
          />
        </span>
      </div>
      <div className="w-full min-w-0 space-y-0.5">
        {subtitle && (
          <div className="text-2xs text-text-muted truncate" title={subtitle}>
            {subtitle}
          </div>
        )}
        <div className="text-2xs text-text-subtle tabular-nums truncate" title={status}>
          {status}
        </div>
      </div>
    </button>
  );
}

// contextualSubtitle returns the per-credential-type hint shown below
// the card title. For connected credentials the server resolves the
// account identity (OAuth display_name, Postgres/Clickhouse user,
// etc.) into `subtitle` — we surface that verbatim and otherwise
// leave the slot empty (the green dot + status text already convey
// "connected"). The unconnected hints are still synthesised here
// because they depend on which connect path the card offers.
function contextualSubtitle(i: Integration, connected: boolean, hasSlots: boolean): string {
  if (connected) {
    return i.subtitle ?? "";
  }
  // Not connected: OAuth and Tailscale both await an explicit user
  // action; manual creds with slots are simply unconfigured.
  if (i.has_oauth || i.has_tailscale_auth) return "Not connected";
  if (hasSlots) return "Not configured";
  return "";
}

function AllIntegrationsModal({
  list,
  onClose,
  onConnect,
  onDisconnect,
}: {
  list: Integration[];
  onClose: () => void;
  onConnect: (i: Integration) => void;
  onDisconnect: (i: Integration) => void;
}) {
  return (
    <Modal onClose={onClose} labelledBy="all-integrations-title">
      <div className="bg-canvas-light border-2 border-navy rounded shadow-lg overflow-hidden w-full max-w-3xl max-h-[80vh] flex flex-col">
        <div className="flex items-center px-5 py-3 bg-navy-100">
          <h2
            id="all-integrations-title"
            className="text-xs uppercase tracking-[.12em] text-navy font-bold"
          >
            All integrations ({list.length})
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="ml-auto text-xl leading-none px-2 py-1 text-navy hover:text-text"
          >
            ✕
          </button>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2.5 p-5 overflow-y-auto">
          {list.map((i) => (
            <Card
              key={i.id}
              integration={i}
              onConnect={() => onConnect(i)}
              onDisconnect={() => onDisconnect(i)}
            />
          ))}
        </div>
      </div>
    </Modal>
  );
}
