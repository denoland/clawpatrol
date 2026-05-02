import type { Integration, Whoami } from "../lib/api";
import { fmtExpiry } from "../lib/format";
import { IntegrationIcon } from "./Logos";
import { oauthRevoke } from "../lib/api";

const PRETTY: Record<string, string> = {
  claude: "Claude",
  codex: "Codex",
  github: "GitHub",
};

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
  onConnect: (id: string) => void;
  onRefresh: () => void;
}) {
  // Credentials are bucketed by profile. The card is "connected" if
  // the device's profile has a token for that integration. Fall back
  // to whoami when no profile is set (legacy single-tenant configs).
  const youKey = profile || whoami?.user || whoami?.host || "";
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2.5">
      {list.map((i) => {
        const me = (i.owners ?? []).find((o) => o.owner === youKey);
        const connected = me?.connected ?? false;
        const clickable = i.has_oauth && !connected;
        return (
          <button
            key={i.id}
            disabled={!i.has_oauth}
            onClick={() => i.has_oauth && onConnect(i.id)}
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
              <IntegrationIcon id={i.id} className="w-[16px] h-[16px] flex-shrink-0" />
              <span className="text-[12px] font-semibold text-[#171717]">{PRETTY[i.id] ?? i.name}</span>
              <span className="ml-auto flex items-center gap-1.5 flex-shrink-0">
                {connected && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      oauthRevoke(i.id, youKey).then(onRefresh);
                    }}
                    className="opacity-0 group-hover:opacity-100 text-[11px] leading-none text-[#a3a3a3] hover:text-[#dc2626] transition-opacity"
                    title="disconnect"
                  >
                    ✕
                  </button>
                )}
                <span
                  className={
                    "w-[6px] h-[6px] rounded-full " +
                    (connected ? "bg-[#22c55e]" : "bg-[#d4d4d4]")
                  }
                />
              </span>
            </div>
            <div className="text-[10px] text-[#737373] tabular-nums w-full truncate">
              {connected
                ? me?.expires_at
                  ? "expires " + fmtExpiry(me.expires_at)
                  : "connected"
                : i.has_oauth
                ? "click to connect"
                : "api key only"}
            </div>
          </button>
        );
      })}
    </div>
  );
}
