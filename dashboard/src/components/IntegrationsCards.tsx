import * as React from "react";
import { useState } from "react";
import type { Integration, TailscaleNodeState } from "../lib/api";
import { clearCredential, oauthRevoke, tailscaleConnect, tailscaleDisconnect } from "../lib/api";
import { credentialTypeLabel } from "../lib/credentialLabels";
import { fmtExpiry } from "../lib/format";
import { CredentialSecretsModal } from "./CredentialSecretsModal";
import { IntegrationIcon } from "./Logos";
import { Modal } from "./Modal";

// Card layout: heading = bare HCL credential name (the unique
// identifier two same-type cards differ by), subtitle = plugin label
// plus optional context (OAuth identity, "not connected", etc.). The
// icon already conveys the plugin type, so prefixing the heading
// truncated the name itself — the part the operator actually needs.

// Cap on visible cards before the overflow button appears. The N-th
// slot is replaced by "+ K more" so the row width stays predictable
// — 3 cards + 1 overflow button keeps the device-page row tidy.
const VISIBLE_CAP = 4;

export function IntegrationsCards({
  list,
  showAll,
  onConnect,
  onRefresh,
}: {
  list: Integration[];
  // When true, render every card in the grid (no overflow button,
  // no "+ K more" modal). Used by the Settings page where the
  // credentials row IS the page and there's space for the full list.
  showAll?: boolean;
  onConnect: (id: string) => void;
  onRefresh: () => void;
}) {
  const [editing, setEditing] = useState<Integration | null>(null);
  const [allOpen, setAllOpen] = useState(false);

  // Sort: connected first, then unconnected, then disabled (no auth
  // path) — preserves declaration order within each bucket.
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

  function disconnect(i: Integration) {
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

  return (
    <>
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
            className="flex items-center justify-center px-3 py-2.5 bg-canvas-light border-1.5 border-dashed border-navy text-xs text-text-muted hover:bg-navy-50 hover:text-text transition-colors"
          >
            + {hiddenCount} more
          </button>
        )}
      </div>

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

// tailscaleStatusLabel renders the credential card's bottom-row hint
// when the credential is *not* connected — the connected branch is
// handled directly by Card. Maps each NodeStateLabel onto the operator-
// facing phrasing the bead specified: NeedsLogin / NeedsMachineAuth
// surfaces the auth URL via the existing card-click handler, so the
// label says "awaiting authentication" to make the action obvious.
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
      // Defensive fallback; `connected` short-circuits the running
      // branch in Card before this helper runs.
      return "connected";
    default:
      return "click to connect";
  }
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
  // Tailscale identities can persist while the live node is *not*
  // running (rejected machine key, expired auth, etc.) — the gateway
  // exposes has_state in that window so the card can offer a Reset
  // path. Without this the operator had to bounce the gateway to
  // recover from a stuck registration.
  const canReset = i.has_tailscale_auth && (i.tailscale_auth?.has_state ?? false);
  const showDisconnect = connected || canReset;
  const status = connected
    ? i.expires_at
      ? "expires " + fmtExpiry(i.expires_at)
      : "connected"
    : i.has_tailscale_auth
      ? tailscaleStatusLabel(i.tailscale_auth?.state)
      : i.has_oauth
        ? "click to connect"
        : hasSlots
          ? "paste secret"
          : "api key only";
  // Plugin display name (e.g. "GitHub", "Postgres"). Falls back to the
  // raw HCL type key for unrecognised plugins.
  const label = credentialTypeLabel(i.type, i.type);
  // Heading shows the bare HCL block name — that's the unique
  // identifier two same-type cards differ by, and the icon already
  // conveys the plugin type. The type label moves into the subtitle.
  const heading = i.name;
  const subtitle = contextualSubtitle(i, connected, hasSlots, label);
  const title = [`${label} · ${i.name}`, `credential: ${i.id}`, `type: ${i.type}`, status].join(
    "\n",
  );
  return (
    <button
      disabled={!clickable && !connected}
      onClick={() => clickable && onConnect()}
      className={
        "group relative flex flex-col items-start gap-2 px-3 py-2.5 bg-canvas-light border-1.5 border-navy text-left transition-colors " +
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
          {showDisconnect && (
            <span
              onClick={(e) => {
                e.stopPropagation();
                onDisconnect();
              }}
              className="opacity-0 group-hover:opacity-100 text-xs leading-none text-text-subtle hover:text-danger-500 transition-opacity cursor-pointer"
              title={connected ? "disconnect" : "reset stored identity"}
            >
              ✕
            </span>
          )}
          <span
            className={
              "w-[9px] h-[9px] rounded-full " + (connected ? "bg-success-500" : "bg-danger-500")
            }
          />
        </span>
      </div>
      <div className="w-full min-w-0 space-y-0.5">
        <div className="text-2xs text-text-muted truncate" title={subtitle}>
          {subtitle}
        </div>
        <div className="text-2xs text-text-subtle tabular-nums truncate" title={status}>
          {status}
        </div>
      </div>
    </button>
  );
}

// contextualSubtitle returns the subtitle shown below the card
// heading: always leads with the plugin label (since the heading no
// longer carries it), followed by the OAuth identity or per-state
// hint. Sources are all non-secret fields on the IntegrationRow
// payload — no secret material is rendered.
function contextualSubtitle(
  i: Integration,
  connected: boolean,
  hasSlots: boolean,
  label: string,
): string {
  // Plugin label always leads the subtitle now that the heading shows
  // just the bare HCL name. OAuth identity (when present) follows.
  const hint = subtitleHint(i, connected, hasSlots);
  return hint ? `${label} · ${hint}` : label;
}

function subtitleHint(i: Integration, connected: boolean, hasSlots: boolean): string {
  if (connected) {
    if (i.display_name) return i.display_name;
    return "";
  }
  if (i.has_tailscale_auth) {
    const s = i.tailscale_auth?.state;
    if (s === "needs_login" || s === "needs_machine_auth") return "awaiting auth";
    if (s === "starting") return "starting";
    if (s === "stopped") return "stopped";
    if (s === "in_use_other_user") return "in use by another user";
    return "not connected";
  }
  if (i.has_oauth) return "not connected";
  if (hasSlots) return "not configured";
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
    <Modal size="lg" title={`All integrations (${list.length})`} onClose={onClose}>
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
    </Modal>
  );
}
