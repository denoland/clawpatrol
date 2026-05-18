import type { Agent } from "../../lib/api";
import { fmtAge, fmtBytes } from "../../lib/format";
import { Sparkline } from "../../components/Sparkline";
import { Card } from "../cards/Card";
import { PageHeader } from "../cards/PageHeader";

// Devices — flat per-agent table. unclaw's DevicesPage edits names,
// approves IPs, and assigns default profiles inline. cl-r3e is
// read-only for everything except credentials, so the row actions
// are dropped; the row just shows what's known.
//
// Gap: unclaw splits "registered device" from "active session"
// (devices carry IPs and tokens; sessions belong to devices and
// inherit a profile). clawpatrol collapses these into a single
// Agent keyed by IP. There's no "Awaiting approval" device list
// because clawpatrol has no device-registration handshake to
// gate on.
//
// Per-credential integration chips have moved to the Profiles page,
// which is the right place to see what a device's profile binds.
export function V2DevicesPage({ agents }: { agents: Agent[] }) {
  const sorted = [...agents].sort((a, b) => a.ip.localeCompare(b.ip));

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Devices"
        subhead="Agents that have connected to this clawpatrol gateway. Click a row in v1 to drill in — v2 is read-only and shows the summary inline."
      />

      <Card title="Devices" count={sorted.length} tight>
        {sorted.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-text-muted">
            No agents have checked in yet.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-canvas-muted text-left text-text-muted text-xs uppercase tracking-wider">
              <tr>
                <th className="px-4 py-2 font-medium">Hostname</th>
                <th className="px-4 py-2 font-medium">IP</th>
                <th className="px-4 py-2 font-medium">OS</th>
                <th className="px-4 py-2 font-medium">Profile</th>
                <th className="px-4 py-2 font-medium text-right">Reqs</th>
                <th className="px-4 py-2 font-medium text-right">In/Out</th>
                <th className="px-4 py-2 font-medium">Activity</th>
                <th className="px-4 py-2 font-medium">Last seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-canvas-dark">
              {sorted.map((a) => (
                <tr key={a.ip}>
                  <td className="px-4 py-2 font-medium truncate max-w-[200px]">
                    {a.hostname || "—"}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs">{a.ip}</td>
                  <td className="px-4 py-2 text-text-muted">{a.os}</td>
                  <td className="px-4 py-2 text-text-muted">{a.profile || "—"}</td>
                  <td className="px-4 py-2 text-right">{a.reqs}</td>
                  <td className="px-4 py-2 text-right text-text-muted text-xs">
                    {fmtBytes(a.bytes_in)} / {fmtBytes(a.bytes_out)}
                  </td>
                  <td className="px-4 py-2">
                    <Sparkline data={a.activity} width={120} height={18} />
                  </td>
                  <td className="px-4 py-2 text-text-muted">{fmtAge(a.last_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
