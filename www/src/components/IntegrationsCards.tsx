import * as React from "react";
import { useState } from "react";
import type { Integration } from "../lib/api";
import { clearCredential, oauthRevoke, tailscaleConnect, tailscaleDisconnect } from "../lib/api";
import { credentialTypeLabel } from "../lib/credentialLabels";
import { fmtExpiry } from "../lib/format";
import { CredentialSecretsModal } from "./CredentialSecretsModal";
import { IntegrationIcon } from "./Logos";

// Bare credential names often look like "pg-writer-cred" — useful as
// identifiers, not as labels. The type maps to the recognizable brand /
// protocol; the bare name is always rendered as metadata so operators
// can still tell two same-type cards apart.

// Cap on visible cards before the overflow button appears. The N-th
// slot is replaced by "+ K more" so the row width stays predictable
// — 3 cards + 1 overflow button keeps the device-page row tidy.
const VISIBLE_CAP = 4;

export function IntegrationsCards({
  list,
  onConnect,
  onRefresh,
}: {
  list: Integration[];
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

  const overflow = sorted.length > VISIBLE_CAP;
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
            className="flex items-center justify-center px-3 py-2.5 bg-white border border-dashed border-[#d4d4d4] rounded text-[12px] text-[#737373] hover:border-[#171717] hover:text-[#171717] transition-colors"
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
      <IntegrationIcon
        id={fallbackId}
        type={fallbackType}
        className="w-[16px] h-[16px] flex-shrink-0"
      />
    );
  }
  return (
    <img
      src={src}
      alt=""
      onError={() => setBroken(true)}
      className="w-[16px] h-[16px] flex-shrink-0 rounded-full object-cover"
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
  const label = credentialTypeLabel(i.type, i.name);
  const title = [label, `credential: ${i.id}`, `type: ${i.type}`, status].join("\n");
  return (
    <button
      disabled={!clickable && !connected}
      onClick={() => clickable && onConnect()}
      className={
        "group relative flex flex-col items-start gap-2 px-3 py-2.5 bg-white border rounded text-left transition-colors " +
        (connected
          ? "border-[#bbf7d0] bg-[#f0fdf4] " +
            (clickable ? "hover:border-[#16a34a] cursor-pointer" : "cursor-default")
          : clickable
            ? "border-[#e5e5e5] hover:border-[#171717] cursor-pointer"
            : "border-[#e5e5e5] cursor-default")
      }
    >
      <div className="flex items-center gap-2 w-full">
        {connected && i.avatar_url ? (
          <OwnerAvatar src={i.avatar_url} fallbackId={i.id} fallbackType={i.type} />
        ) : (
          <IntegrationIcon id={i.id} type={i.type} className="w-[16px] h-[16px] flex-shrink-0" />
        )}
        <span className="text-[12px] font-semibold text-[#171717] truncate" title={title}>
          {i.display_name ? `${label} (${i.display_name})` : label}
        </span>
        <span className="ml-auto flex items-center gap-1.5 flex-shrink-0">
          {connected && (
            <span
              onClick={(e) => {
                e.stopPropagation();
                onDisconnect();
              }}
              className="opacity-0 group-hover:opacity-100 text-[11px] leading-none text-[#a3a3a3] hover:text-[#dc2626] transition-opacity cursor-pointer"
              title="disconnect"
            >
              ✕
            </span>
          )}
          <span
            className={
              "w-[6px] h-[6px] rounded-full " + (connected ? "bg-[#22c55e]" : "bg-[#d4d4d4]")
            }
          />
        </span>
      </div>
      <div className="w-full min-w-0 space-y-0.5">
        <div className="text-[10px] text-[#737373] tabular-nums truncate" title={i.id}>
          <span className="font-mono">{i.id}</span>
        </div>
        <div className="text-[10px] text-[#a3a3a3] tabular-nums truncate" title={status}>
          {status}
        </div>
      </div>
    </button>
  );
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
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/30"
      onClick={onClose}
    >
      <div
        className="bg-white border border-[#e5e5e5] rounded shadow-lg w-full max-w-3xl max-h-[80vh] overflow-y-auto p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <div className="text-[14px] font-semibold text-[#171717]">
            All integrations ({list.length})
          </div>
          <button
            onClick={onClose}
            className="text-[#a3a3a3] hover:text-[#171717] text-[14px] leading-none"
          >
            ✕
          </button>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2.5">
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
    </div>
  );
}
