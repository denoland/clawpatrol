import * as React from "react";
import { useState } from "react";
import type { Integration, Whoami } from "../lib/api";
import { fmtExpiry } from "../lib/format";
import { IntegrationIcon } from "./Logos";
import { clearCredential, oauthRevoke } from "../lib/api";
import { CredentialSecretsModal } from "./CredentialSecretsModal";

// Display name by credential plugin type. Bare credential names
// often look like "pg-writer-cred" — useful as identifier, not as a
// label. The type maps to the recognizable brand / protocol; the
// bare name shows up as a subtitle so operators can still tell two
// "Postgres" cards apart.
const TYPE_LABEL: Record<string, string> = {
  anthropic_oauth_subscription: "Claude",
  anthropic_manual_key: "Claude (API key)",
  openai_codex_oauth: "Codex",
  github_oauth: "GitHub",
  notion_oauth: "Notion",
  postgres_credential: "Postgres",
  clickhouse_credential: "ClickHouse",
  mtls_credential: "mTLS",
  slack_tokens: "Slack",
  telegram_bot_token: "Telegram",
  gemini_api_key: "Gemini",
  aws_eks_credential: "AWS EKS",
  bearer_token: "Bearer token",
  header_token: "Header token",
  cookie_token: "Cookie token",
};

// Cap on visible cards before the overflow button appears. The N-th
// slot is replaced by "+ K more" so the row width stays predictable
// — 3 cards + 1 overflow button keeps the device-page row tidy.
const VISIBLE_CAP = 4;

export function IntegrationsCards({
  list,
  whoami,
  profile,
  onConnect,
  onRefresh,
}: {
  list: Integration[];
  whoami: Whoami | null;
  profile?: string;
  onConnect: (id: string, profile?: string) => void;
  onRefresh: () => void;
}) {
  const youKey = profile || whoami?.user || whoami?.host || "";
  const [editing, setEditing] = useState<Integration | null>(null);
  const [allOpen, setAllOpen] = useState(false);

  // Sort: connected first (most relevant), then unconnected, then
  // already-disabled ones (no auth path) — preserves declaration
  // order within each bucket.
  const sorted = [...list].sort((a, b) => {
    const score = (i: Integration) => {
      const me = (i.owners ?? []).find((o) => o.owner === youKey);
      if (me?.connected) return 0;
      if (i.has_oauth || (i.slots && i.slots.length > 0)) return 1;
      return 2;
    };
    return score(a) - score(b);
  });

  const overflow = sorted.length > VISIBLE_CAP;
  const visible = overflow ? sorted.slice(0, VISIBLE_CAP - 1) : sorted;
  const hiddenCount = sorted.length - visible.length;

  function handleConnect(i: Integration) {
    if (i.has_oauth) {
      onConnect(i.id, profile);
      return;
    }
    if (i.slots && i.slots.length > 0) {
      setEditing(i);
    }
  }

  function disconnect(i: Integration) {
    if (i.has_oauth) {
      oauthRevoke(i.id, youKey).then(onRefresh);
    } else {
      clearCredential(i.id, youKey).then(onRefresh);
    }
  }

  return (
    <>
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2.5">
        {visible.map((i) => (
          <Card
            key={i.id}
            integration={i}
            youKey={youKey}
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
          youKey={youKey}
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
          owner={youKey}
          onClose={() => setEditing(null)}
          onSaved={onRefresh}
        />
      )}
    </>
  );
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
  youKey,
  onConnect,
  onDisconnect,
}: {
  integration: Integration;
  youKey: string;
  onConnect: () => void;
  onDisconnect: () => void;
}) {
  const me = (i.owners ?? []).find((o) => o.owner === youKey);
  const connected = me?.connected ?? false;
  const hasSlots = (i.slots?.length ?? 0) > 0;
  const clickable = (i.has_oauth || hasSlots) && !connected;
  const subtitle = connected
    ? me?.expires_at
      ? "expires " + fmtExpiry(me.expires_at)
      : "connected"
    : i.has_oauth
      ? "click to connect"
      : hasSlots
        ? "paste secret"
        : "api key only";
  return (
    <button
      disabled={!clickable && !connected}
      onClick={() => clickable && onConnect()}
      className={
        "group relative flex flex-col items-start gap-2 px-3 py-2.5 bg-white border rounded text-left transition-colors " +
        (connected
          ? "border-[#bbf7d0] bg-[#f0fdf4]"
          : clickable
            ? "border-[#e5e5e5] hover:border-[#171717] cursor-pointer"
            : "border-[#e5e5e5] cursor-default")
      }
    >
      <div className="flex items-center gap-2 w-full">
        {connected && me?.avatar_url ? (
          <OwnerAvatar src={me.avatar_url} fallbackId={i.id} fallbackType={i.type} />
        ) : (
          <IntegrationIcon id={i.id} type={i.type} className="w-[16px] h-[16px] flex-shrink-0" />
        )}
        <span
          className="text-[12px] font-semibold text-[#171717] truncate"
          title={me?.display_name ?? i.id}
        >
          {(() => {
            const label = TYPE_LABEL[i.type] ?? i.name;
            return me?.display_name ? `${label} (${me.display_name})` : label;
          })()}
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
      <div className="text-[10px] text-[#737373] tabular-nums w-full truncate" title={i.id}>
        {/* Connected → show expiry / "connected". Otherwise show the
            bare credential name so two same-type cards (pg-writer +
            pg-readonly) are distinguishable; falls back to the status
            text when type and name match (claude / codex / github). */}
        {connected
          ? subtitle
          : TYPE_LABEL[i.type] && i.id !== (TYPE_LABEL[i.type] ?? "").toLowerCase()
            ? i.id
            : subtitle}
      </div>
    </button>
  );
}

function AllIntegrationsModal({
  list,
  youKey,
  onClose,
  onConnect,
  onDisconnect,
}: {
  list: Integration[];
  youKey: string;
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
              youKey={youKey}
              onConnect={() => onConnect(i)}
              onDisconnect={() => onDisconnect(i)}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
