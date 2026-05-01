import { useMemo } from "react";
import { deleteAgent, type Agent, type Integration, type Whoami } from "../lib/api";
import { fmtBytes } from "../lib/format";
import { DeviceIcon } from "./Logos";
import { Sparkline } from "./Sparkline";
import { LiveRequests } from "./LiveRequests";
import { RulesPanel } from "./RulesPanel";
import { IntegrationsCards } from "./IntegrationsCards";
import { SessionsTable } from "./SessionsTable";

export function DevicePage({
  ip,
  agents,
  integrations,
  whoami,
  onBack,
  onConnect,
  onRefresh,
}: {
  ip: string;
  agents: Agent[];
  integrations: Integration[];
  whoami: Whoami | null;
  onBack: () => void;
  onConnect: (id: string) => void;
  onRefresh: () => void;
}) {
  const a = useMemo(() => agents.find((x) => x.ip === ip) ?? null, [agents, ip]);
  if (!a) {
    return (
      <main className="mx-auto w-full max-w-[1100px] px-4 sm:px-6 py-5">
        <button onClick={onBack} className="text-[11px] text-[#737373] hover:text-[#171717] mb-3">
          ← back
        </button>
        <div className="bg-white border border-[#e5e5e5] rounded px-5 py-8 text-center text-[12px] text-[#a3a3a3]">
          no agent with ip {ip}
        </div>
      </main>
    );
  }

  const dev = a;
  const total = dev.bytes_in + dev.bytes_out;
  const allForUser = integrations;

  async function remove() {
    if (!confirm(`Remove ${dev.hostname || dev.ip} from clawpatrol?\n\nThis clears the device's tracking + owner mapping. Tailscale node stays — remove from admin console if you want a hard kick.`)) return;
    try {
      await deleteAgent(dev.ip);
      onBack();
      onRefresh();
    } catch (e: any) {
      alert("delete failed: " + (e?.message ?? e));
    }
  }

  return (
    <main className="mx-auto w-full max-w-[1100px] px-4 sm:px-6 py-5 space-y-5">
      <div className="flex items-center justify-between">
        <button onClick={onBack} className="text-[11px] text-[#737373] hover:text-[#171717]">
          ← back
        </button>
        <button
          onClick={remove}
          className="text-[11px] text-[#a3a3a3] hover:text-[#dc2626] transition-colors"
          title="forget this device"
        >
          delete device
        </button>
      </div>

      {/* device header card */}
      <section className="bg-white border border-[#e5e5e5] rounded">
        <div className="flex items-center gap-3 px-5 py-4 border-b border-[#e5e5e5]">
          <DeviceIcon os={a.os} hostname={a.hostname} ua={a.ua} className="w-[18px] h-[18px] text-[#525252]" />
          <div className="min-w-0">
            <div className="text-[15px] font-semibold text-[#171717] truncate">{a.hostname || a.ip}</div>
            <div className="text-[11px] text-[#737373] truncate">
              {a.user || "—"} · {a.ip}
              {a.os && <> · <span className="uppercase tracking-[.08em]">{a.os}</span></>}
            </div>
          </div>
          <div className="ml-auto flex items-center gap-3">
            <Sparkline data={a.activity} width={160} height={26} />
            <div className="text-right">
              <div className="text-[10px] uppercase tracking-[.09em] text-[#a3a3a3]">TRAFFIC</div>
              <div className="text-[12px] tabular-nums">{fmtBytes(total)}</div>
            </div>
            <div className="text-right">
              <div className="text-[10px] uppercase tracking-[.09em] text-[#a3a3a3]">REQS</div>
              <div className="text-[12px] tabular-nums">{a.reqs}</div>
            </div>
          </div>
        </div>
      </section>

      {/* agents (sessions) running on this device */}
      <SessionsTable sessions={a.sessions ?? []} />

      {/* live request stream filtered by this device */}
      <LiveRequests agentIP={a.ip} height="360px" />

      {/* integrations management for this user */}
      <IntegrationsCards
        list={allForUser}
        whoami={whoami}
        onConnect={onConnect}
        onRefresh={onRefresh}
      />

      {/* rules — per-device scope (with global rules layered in) */}
      <RulesPanel deviceIP={a.ip} />
    </main>
  );
}
