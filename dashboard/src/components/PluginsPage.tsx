import { useEffect, useState } from "react";
import { getPlugins, type Plugin } from "../lib/api";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";

// PluginsPage lists the loaded external plugins and the permissions
// each runs with. Network is declared by the plugin and approved on
// first load (recorded in clawpatrol.lock.hcl); a plugin blocked by a
// permission escalation never loads, so it does not appear here — that
// failure surfaces at gateway start / `clawpatrol validate`.
export function PluginsPage() {
  const [plugins, setPlugins] = useState<Plugin[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getPlugins()
      .then(setPlugins)
      .catch((e: Error) => setErr(String(e.message ?? e)));
  }, []);

  return (
    <Main>
      <PageTitle trail={[{ label: "Plugins" }]} />

      <p className="text-sm text-text-muted mb-5 max-w-3xl">
        External plugins run sandboxed. Each declares its own network need; the gateway records the
        approved permissions in <code className="font-mono text-xs">clawpatrol.lock.hcl</code> on
        first load and refuses to start a plugin whose update asks for more, until you re-approve
        it. Filesystem access and turning the sandbox off are operator-only.
      </p>

      {err && (
        <div className="bg-canvas border-1.5 border-navy px-4 py-3 text-xs text-danger-500">
          {err}
        </div>
      )}

      {!err && plugins === null && <div className="text-sm text-text-muted">Loading…</div>}

      {!err && plugins?.length === 0 && (
        <div className="bg-canvas border-1.5 border-navy px-4 py-6 text-sm text-text-muted">
          No external plugins are loaded.
        </div>
      )}

      <div className="space-y-4">
        {plugins?.map((p) => (
          <PluginCard key={p.name} p={p} />
        ))}
      </div>
    </Main>
  );
}

function PluginCard({ p }: { p: Plugin }) {
  return (
    <section className="bg-canvas border-1.5 border-navy overflow-hidden">
      <div className="flex items-center gap-3 flex-wrap px-4 py-3 bg-navy-100 border-b border-navy">
        <h2 className="font-mono text-sm text-navy font-bold">{p.name}</h2>
        {p.version && <span className="font-mono text-2xs text-text-muted">v{p.version}</span>}
        <div className="ml-auto flex items-center gap-2">
          <NetworkBadge network={p.network} />
          <SandboxBadge mode={p.sandboxMode} />
        </div>
      </div>

      {p.sandboxWarning && (
        <div className="px-4 py-2 bg-butter-100 border-b border-butter-300 text-xs text-rust-700">
          Reduced sandbox: {p.sandboxWarning}
        </div>
      )}

      <div className="px-4 py-3 space-y-3">
        <Field label="Source">
          <span className="font-mono text-xs text-text-muted break-all">{p.source}</span>
        </Field>
        {p.approvedHash && (
          <Field label="Approved">
            <span className="font-mono text-2xs text-text-muted break-all">{p.approvedHash}</span>
          </Field>
        )}
        <TypeGroup label="Credentials" items={p.credentials} />
        <TypeGroup label="Tunnels" items={p.tunnels} />
        <TypeGroup label="Endpoints" items={p.endpoints} />
        <TypeGroup label="Facets" items={p.facets} />
      </div>
    </section>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-baseline gap-1 sm:gap-3">
      <span className="font-mono text-2xs uppercase tracking-wider text-navy font-bold sm:w-28 shrink-0">
        {label}
      </span>
      {children}
    </div>
  );
}

function TypeGroup({ label, items }: { label: string; items?: string[] }) {
  if (!items || items.length === 0) return null;
  return (
    <Field label={label}>
      <div className="flex flex-wrap gap-1.5">
        {items.map((t) => (
          <span
            key={t}
            className="font-mono text-2xs text-navy bg-navy-100 px-1.5 py-0.5 squircle-md"
          >
            {t}
          </span>
        ))}
      </div>
    </Field>
  );
}

function NetworkBadge({ network }: { network: string }) {
  const outbound = network === "outbound";
  return (
    <Badge
      tone={outbound ? "warn" : "calm"}
      title={
        outbound
          ? "The plugin can dial the network directly."
          : "No network: the plugin only talks to the gateway."
      }
    >
      net: {network || "none"}
    </Badge>
  );
}

function SandboxBadge({ mode }: { mode: string }) {
  const off = mode === "off";
  return (
    <Badge
      tone={off ? "danger" : "calm"}
      title={off ? "Sandbox off — full host access (fully trusted)." : `Sandboxed via ${mode}.`}
    >
      sandbox: {mode}
    </Badge>
  );
}

function Badge({
  tone,
  title,
  children,
}: {
  tone: "calm" | "warn" | "danger";
  title?: string;
  children: React.ReactNode;
}) {
  const tones: Record<string, string> = {
    calm: "bg-navy-100 text-navy",
    warn: "bg-butter-100 text-rust-700",
    danger: "bg-danger-500 text-canvas",
  };
  return (
    <span
      title={title}
      className={`font-mono text-2xs uppercase tracking-wider px-1.5 py-0.5 squircle-md ${tones[tone]}`}
    >
      {children}
    </span>
  );
}
