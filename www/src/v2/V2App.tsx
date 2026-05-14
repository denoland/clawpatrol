import { useEffect, useState } from "react";
import {
  getHITLPending,
  getState,
  type Agent,
  type HITLPending,
  type Integration,
} from "../lib/api";
import { ConnectModal } from "../components/ConnectModal";
import { V2Shell } from "./V2Shell";
import { OverviewPage } from "./pages/OverviewPage";
import { V2ActionsPage } from "./pages/ActionsPage";
import { V2RulesPage } from "./pages/RulesPage";
import { V2AnalyticsPage } from "./pages/AnalyticsPage";
import { ProfilesPage } from "./pages/ProfilesPage";
import { V2DevicesPage } from "./pages/DevicesPage";
import { V2SettingsPage } from "./pages/SettingsPage";

export type V2Page =
  | "overview"
  | "actions"
  | "rules"
  | "analytics"
  | "profiles"
  | "devices"
  | "settings";

export type V2Route = { page: V2Page } | { page: "actions"; actionId: string };

// Polecat decisions for this v2 dashboard:
//   1. Route prefix is `#/v2` (hash routing, matches existing app
//      shell). The toggle in the existing dashboard's header points
//      to `#/v2`; the toggle in this shell points to `#/`.
//   2. File layout: `www/src/v2/` self-contained, with cards/ and
//      pages/ subfolders mirroring unclaw's component organisation.
//      Keeps the diff and the namespace clean — nothing in `www/
//      src/components/` knows about v2 except `ConnectModal` and
//      `SettingsPage`, which v2 imports verbatim.
//   3. Data: v2 talks to clawpatrol's existing API (`/api/state`,
//      `/api/rules`, etc.) since `cl-r3e` forbids adding new
//      endpoints. unclaw-shaped concepts that don't exist in
//      clawpatrol (named approvers, named profiles with default
//      LLM/Human approver pickers, per-device session split,
//      `/api/decisions`) render as empty-state placeholders.
//   4. The Settings tab embeds the existing clawpatrol Settings
//      page verbatim — credential modals, HCL viewer and all —
//      per the cl-r3e read-only constraint that explicitly
//      preserves cl-jli / cl-fq1 / cl-003 / cl-irg's modal work.
export function parseV2Route(hash: string): V2Route | null {
  // Strip the leading `#` and any query string.
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  const qIdx = raw.indexOf("?");
  const path = qIdx < 0 ? raw : raw.slice(0, qIdx);
  if (!path.startsWith("/v2")) return null;
  const rest = path.slice("/v2".length);
  if (rest === "" || rest === "/") return { page: "overview" };
  const actM = rest.match(/^\/actions\/([^/]+)$/);
  if (actM) return { page: "actions", actionId: decodeURIComponent(actM[1]) };
  const seg = rest.replace(/^\//, "").split("/")[0];
  // Approvals were folded into the Actions page — keep old links working.
  if (seg === "approvals") return { page: "actions" };
  const pages: V2Page[] = [
    "overview",
    "actions",
    "rules",
    "analytics",
    "profiles",
    "devices",
    "settings",
  ];
  if ((pages as string[]).includes(seg)) return { page: seg as V2Page };
  return { page: "overview" };
}

export function V2App({ route }: { route: V2Route }) {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [pending, setPending] = useState<HITLPending[]>([]);
  const [connectId, setConnectId] = useState<string | null>(null);

  async function refresh() {
    try {
      const [s, p] = await Promise.all([
        getState(),
        getHITLPending().catch(() => [] as HITLPending[]),
      ]);
      setIntegrations(s.integrations || []);
      setAgents(s.agents || []);
      setPending(p || []);
    } catch {
      /* swallow */
    }
  }

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, []);

  return (
    <V2Shell current={route.page} hitlCount={pending.length}>
      {route.page === "overview" && (
        <OverviewPage agents={agents} integrations={integrations} pending={pending} />
      )}
      {route.page === "actions" && (
        <V2ActionsPage
          agents={agents}
          pending={pending}
          onRefresh={refresh}
          actionId={"actionId" in route ? route.actionId : undefined}
        />
      )}
      {route.page === "rules" && <V2RulesPage agents={agents} />}
      {route.page === "analytics" && <V2AnalyticsPage agents={agents} />}
      {route.page === "profiles" && <ProfilesPage agents={agents} integrations={integrations} />}
      {route.page === "devices" && <V2DevicesPage agents={agents} />}
      {route.page === "settings" && (
        <V2SettingsPage
          integrations={integrations}
          onConnect={(id) => setConnectId(id)}
          onRefresh={refresh}
        />
      )}
      {connectId && (
        <ConnectModal
          id={connectId}
          oauth={integrations.find((i) => i.id === connectId)?.oauth}
          onClose={() => setConnectId(null)}
          onDone={() => {
            setConnectId(null);
            refresh();
          }}
        />
      )}
    </V2Shell>
  );
}
