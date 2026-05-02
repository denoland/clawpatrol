import { useEffect, useState } from "react";
import { AgentsTable } from "./components/AgentsTable";
import { ConnectModal } from "./components/ConnectModal";
import { DevicePage } from "./components/DevicePage";
import { LiveRequests } from "./components/LiveRequests";
import { OnboardPage } from "./components/OnboardPage";
import { AddDeviceModal } from "./components/AddDeviceModal";
import { SettingsModal } from "./components/SettingsModal";
import { HITLBar } from "./components/HITLBar";
import { getStatus, getAgents, getWhoami, type Integration, type Agent, type Whoami } from "./lib/api";

function parseRoute(): { name: "main" } | { name: "device"; ip: string } | { name: "onboard"; code: string } {
  const h = window.location.hash;
  if (h.startsWith("#/onboard/")) return { name: "onboard", code: decodeURIComponent(h.slice("#/onboard/".length)) };
  const m = h.match(/^#\/device\/(.+)$/);
  if (m) return { name: "device", ip: decodeURIComponent(m[1]) };
  return { name: "main" };
}

export default function App() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [whoami, setWhoami] = useState<Whoami | null>(null);
  const [connectId, setConnectId] = useState<string | null>(null);
  const [showAddDevice, setShowAddDevice] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [route, setRoute] = useState(parseRoute());

  useEffect(() => {
    const onHash = () => setRoute(parseRoute());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  async function refresh() {
    try {
      const [i, a, w] = await Promise.all([getStatus(), getAgents(), getWhoami()]);
      setIntegrations(i || []);
      setAgents(a || []);
      setWhoami(w);
    } catch {
      /* swallow */
    }
  }

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, []);

  function navigate(hash: string) {
    window.location.hash = hash;
    setRoute(parseRoute());
  }

  return (
    <div className="flex flex-col min-h-screen">
      {route.name === "main" ? (
        <main className="flex-1 mx-auto w-full max-w-[1100px] px-4 sm:px-6 py-8 space-y-8">
          <div className="flex items-center gap-4">
            <h1 className="font-serif text-[44px] sm:text-[56px] leading-none tracking-tight text-[#171717]">
              clawpatrol
            </h1>
            <button
              onClick={() => setShowAddDevice(true)}
              className="w-[36px] h-[36px] rounded-full border border-[#e5e5e5] text-[#525252] text-[22px] leading-none flex items-center justify-center hover:border-[#171717] hover:text-[#171717] transition-colors"
              title="add device"
            >
              +
            </button>
            <button
              onClick={() => setShowSettings(true)}
              className="w-[36px] h-[36px] rounded-full border border-[#e5e5e5] text-[#525252] flex items-center justify-center hover:border-[#171717] hover:text-[#171717] transition-colors"
              title="settings (gateway.hcl)"
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="3" />
                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
              </svg>
            </button>
          </div>
          <section className="bg-white border border-[#e5e5e5] rounded overflow-hidden">
            <div className="overflow-x-auto">
              <AgentsTable agents={agents} onSelect={(ip) => navigate("#/device/" + encodeURIComponent(ip))} />
            </div>
          </section>
          <HITLBar />
          <LiveRequests height="420px" />
        </main>
      ) : route.name === "onboard" ? (
        <OnboardPage code={route.code} onBack={() => navigate("")} />
      ) : (
        <DevicePage
          ip={route.ip}
          agents={agents}
          integrations={integrations}
          whoami={whoami}
          onBack={() => navigate("")}
          onConnect={(id) => setConnectId(id)}
          onRefresh={refresh}
        />
      )}
      {showAddDevice && <AddDeviceModal publicURL={whoami?.public_url} onClose={() => setShowAddDevice(false)} />}
      {showSettings && <SettingsModal onClose={() => setShowSettings(false)} onSaved={refresh} />}
      {connectId && (
        <ConnectModal
          id={connectId}
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
