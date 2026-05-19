import { useEffect, useState } from "react";
import { AgentsTable } from "./components/AgentsTable";
import { AnalyticsPage } from "./components/AnalyticsPage";
import { ConnectModal } from "./components/ConnectModal";
import { DevicePage } from "./components/DevicePage";
import { Header } from "./components/Header";
import { HITLBar } from "./components/HITLBar";
import { LiveRequests } from "./components/LiveRequests";
import { Main } from "./components/Main";
import { OnboardPage } from "./components/OnboardPage";
import { RequestDetailPage } from "./components/RequestDetailPage";
import { SettingsPage } from "./components/SettingsPage";
import { getState, type Agent, type Integration, type UpdateBanner, type Whoami } from "./lib/api";

type Route =
  | { name: "main" }
  | { name: "device"; ip: string }
  | { name: "analytics"; ip?: string }
  | { name: "onboard"; code: string }
  | { name: "request"; id: string }
  | { name: "settings" };

function parseRoute(): Route {
  const raw = window.location.hash;
  const qi = raw.indexOf("?");
  const h = qi < 0 ? raw : raw.slice(0, qi);
  if (h.startsWith("#/onboard/"))
    return {
      name: "onboard",
      code: decodeURIComponent(h.slice("#/onboard/".length)),
    };
  const r = h.match(/^#\/request\/([^/]+)$/);
  if (r) return { name: "request", id: decodeURIComponent(r[1]) };
  if (h === "#/settings") return { name: "settings" };
  if (h === "#/analytics") return { name: "analytics" };
  const a = h.match(/^#\/analytics\/([^/]+)$/);
  if (a) return { name: "analytics", ip: decodeURIComponent(a[1]) };
  // Legacy device/IP/analytics URL
  const da = h.match(/^#\/device\/([^/]+)\/analytics$/);
  if (da) return { name: "analytics", ip: decodeURIComponent(da[1]) };
  const m = h.match(/^#\/device\/([^/]+)$/);
  if (m) return { name: "device", ip: decodeURIComponent(m[1]) };
  return { name: "main" };
}

export default function App() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [whoami, setWhoami] = useState<Whoami | null>(null);
  const [update, setUpdate] = useState<UpdateBanner | null>(null);
  const [connectId, setConnectId] = useState<string | null>(null);
  const [route, setRoute] = useState(parseRoute());

  useEffect(() => {
    const onHash = () => setRoute(parseRoute());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  async function refresh() {
    try {
      // Single round-trip; getState ETags so the no-change path is a
      // 304 (no body, no JSON parse). Replaces three parallel fetches
      // that ran every 3 s — one bundled fetch every 5 s now.
      const s = await getState();
      setIntegrations(s.integrations || []);
      setAgents(s.agents || []);
      setWhoami(s.whoami);
      setUpdate(s.update ?? null);
    } catch {
      /* swallow */
    }
  }

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, []);

  function navigate(hash: string) {
    window.location.hash = hash;
    setRoute(parseRoute());
  }

  return (
    <div className="flex flex-col min-h-screen">
      <UpdateNotice update={update} />
      <Header whoami={whoami} />
      {route.name === "main" ? (
        <Main>
          <section className="bg-canvas-light border-1.5 border-navy overflow-hidden">
            <div className="overflow-x-auto">
              <AgentsTable
                agents={agents}
                integrations={integrations}
                onSelect={(ip) => navigate("#/device/" + encodeURIComponent(ip))}
              />
            </div>
          </section>
          <HITLBar />
          <LiveRequests height="420px" />
        </Main>
      ) : route.name === "analytics" ? (
        <AnalyticsPage ip={route.ip} agents={agents} />
      ) : route.name === "request" ? (
        <RequestDetailPage id={route.id} agents={agents} />
      ) : route.name === "onboard" ? (
        <OnboardPage code={route.code} />
      ) : route.name === "settings" ? (
        <SettingsPage
          integrations={integrations}
          onConnect={(id) => setConnectId(id)}
          onRefresh={refresh}
        />
      ) : (
        <DevicePage
          ip={route.ip}
          agents={agents}
          integrations={integrations}
          onBack={() => navigate("")}
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
    </div>
  );
}

function UpdateNotice({ update }: { update: UpdateBanner | null }) {
  if (!update?.update_available) return null;
  const dismissKey = "clawpatrol:update-dismissed:" + update.latest;
  const [dismissed, setDismissed] = useState(
    typeof localStorage !== "undefined" && localStorage.getItem(dismissKey) === "1",
  );
  if (dismissed) return null;
  return (
    <div className="bg-butter-100 border-b border-butter-300 px-4 sm:px-6 py-2 text-xs text-butter-900 flex items-center justify-between gap-3">
      <div className="flex-1">
        <span className="font-semibold">clawpatrol {update.latest}</span>
        {" available — "}
        <a
          href={update.url}
          target="_blank"
          rel="noopener noreferrer"
          className="underline hover:no-underline"
        >
          release notes
        </a>
        {update.advisory && <span className="ml-2 text-rust-700">({update.advisory})</span>}
      </div>
      <button
        onClick={() => {
          localStorage.setItem(dismissKey, "1");
          setDismissed(true);
        }}
        className="text-butter-900 hover:text-text text-sm leading-none px-1"
        title="dismiss"
      >
        &times;
      </button>
    </div>
  );
}
