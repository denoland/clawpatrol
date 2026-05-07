// Devices table — flat per-device summary. Click row → device page.

import type { Agent, Integration } from "../lib/api";
import { fmtBytes } from "../lib/format";
import { DeviceIcon } from "./Logos";
import { Sparkline } from "./Sparkline";
import { IntegrationStack } from "./IntegrationStack";

export function AgentsTable({
  agents,
  integrations,
  onSelect,
}: {
  agents: Agent[];
  integrations?: Integration[];
  onSelect?: (ip: string) => void;
}) {
  // id → Integration lookup so the icon stack can pick the right
  // logo per credential type (postgres/slack/etc, not just the
  // hardcoded claude/codex/github trio).
  const byId = new Map<string, Integration>();
  for (const i of integrations ?? []) byId.set(i.id, i);
  const stable = [...(agents ?? [])].sort((a, b) => a.ip.localeCompare(b.ip));
  return (
    <table className="w-full table-fixed border-collapse bg-white" style={{ minWidth: 760 }}>
      <colgroup>
        <col style={{ width: 240 }} />
        <col style={{ width: 140 }} />
        <col style={{ width: 200 }} />
        <col style={{ width: 60 }} />
        <col />
        <col style={{ width: 110 }} />
      </colgroup>
      <thead>
        <tr className="border-b border-[#e5e5e5]">
          <Th>DEVICE</Th>
          <Th className="hidden md:table-cell">PROFILE</Th>
          <Th>ACTIVITY</Th>
          <Th className="text-right">REQS</Th>
          <Th className="hidden lg:table-cell">IP</Th>
          <Th>INTEGRATIONS</Th>
          <Th className="w-[32px]">{""}</Th>
        </tr>
      </thead>
      <tbody>
        {stable.length === 0 && (
          <tr>
            <td colSpan={7} className="px-5 py-8 text-center text-[11px] text-[#a3a3a3]">
              It's empty in here
            </td>
          </tr>
        )}
        {stable.map((a) => {
          const total = a.bytes_in + a.bytes_out;
          return (
            <tr
              key={a.ip}
              onClick={() => onSelect?.(a.ip)}
              className="border-b border-[#f5f5f5] cursor-pointer hover:bg-[#f9f9f9] transition-colors"
            >
              <Td>
                <div className="flex items-center gap-1.5 min-w-0">
                  <span className="w-[5px] h-[5px] rounded-full bg-[#22c55e] flex-shrink-0" />
                  <DeviceIcon
                    os={a.os}
                    hostname={a.hostname}
                    ua={a.ua}
                    className="w-[13px] h-[13px] text-[#525252] flex-shrink-0"
                  />
                  <span className="text-[13px] font-semibold text-[#171717] truncate">
                    {a.hostname || a.ip}
                  </span>
                </div>
                <div className="md:hidden text-[10px] text-[#a3a3a3] truncate mt-0.5">
                  {a.profile || "—"}
                </div>
              </Td>
              <Td className="hidden md:table-cell text-[11px] text-[#525252] truncate">
                {a.profile || "—"}
              </Td>
              <Td>
                <div className="flex items-center gap-2">
                  <Sparkline data={a.activity} width={120} height={16} />
                  <span className="text-[10px] text-[#737373] tabular-nums whitespace-nowrap">
                    {fmtBytes(total)}
                  </span>
                </div>
              </Td>
              <Td className="text-[11px] text-[#525252] tabular-nums text-right">{a.reqs}</Td>
              <Td className="hidden lg:table-cell text-[11px] text-[#737373] tabular-nums truncate" title={[a.external_ipv4, a.external_ipv6].filter(Boolean).join(" / ") || `wg ${a.ip}`}>
                {a.external_ipv4 || a.external_ipv6 || a.ip}
              </Td>
              <Td>
                <IntegrationStack
                  items={(a.integrations ?? []).map((id) => {
                    const it = byId.get(id);
                    // Pick the owner row matching this device's profile
                    // so two profiles connected to different GH accounts
                    // surface distinct avatars in their respective rows.
                    const owner = it?.owners?.find((o) => o.owner === a.profile)
                      ?? it?.owners?.[0];
                    return {
                      id,
                      type: it?.type,
                      avatar_url: owner?.avatar_url,
                    };
                  })}
                />
              </Td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function Th({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <th
      className={
        "px-3 sm:px-[14px] py-[9px] text-left text-[10px] uppercase tracking-[.12em] text-[#a3a3a3] font-medium bg-white " +
        className
      }
    >
      {children}
    </th>
  );
}

function Td({
  children,
  className = "",
  ...rest
}: {
  children: React.ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <td className={"px-3 sm:px-[14px] py-[9px] align-middle overflow-hidden " + className} {...rest}>
      {children}
    </td>
  );
}
