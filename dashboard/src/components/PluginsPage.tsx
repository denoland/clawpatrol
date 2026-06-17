import { useCallback, useEffect, useState } from "react";
import { approvePlugin, getPlugins, type Plugin } from "../lib/api";
import { Button } from "./Button";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";

// PluginsPage lists the external plugins and the permissions each
// runs with. Network is declared by the plugin and approved on first
// load (recorded in clawpatrol.lock.hcl). A plugin the gateway
// refused to load — chiefly one whose upgrade escalated its
// permissions — is shown as a blocked card with the reason and the
// re-approve command.
export function PluginsPage() {
  const [plugins, setPlugins] = useState<Plugin[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    getPlugins()
      .then(setPlugins)
      .catch((e: Error) => setErr(String(e.message ?? e)));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <Main>
      <PageTitle trail={[{ label: "Plugins" }]} />

      <p className="text-sm text-text-muted mb-5 max-w-3xl">
        External plugins run sandboxed. Each declares its own network need; the gateway records the
        approved permissions in <code className="font-mono text-xs">clawpatrol.lock.hcl</code> on
        first load and refuses to start a plugin whose update asks for more — shown below as a
        blocked plugin until you re-approve it. Network and egress are recorded on first load; a
        plugin that declares it must run <span className="font-bold">privileged</span> (sandbox off,
        full host access) is held back until you approve it explicitly. Granting extra filesystem
        read paths stays operator-only.
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
        {plugins?.map((p) =>
          p.blocked ? (
            <BlockedCard key={p.name} p={p} onApproved={load} />
          ) : (
            <PluginCard key={p.name} p={p} />
          ),
        )}
      </div>
    </Main>
  );
}

// BlockedCard surfaces a plugin the gateway refused to load — almost
// always a permission escalation across an upgrade. It shows the
// reason, an Approve button (re-records the lockfile and reloads), and
// the equivalent CLI command.
function BlockedCard({ p, onApproved }: { p: Plugin; onApproved: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function approve() {
    setBusy(true);
    setErr(null);
    try {
      await approvePlugin(p.name);
      onApproved();
    } catch (e) {
      setErr(String((e as Error).message ?? e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="bg-canvas border-1.5 border-danger-500 overflow-hidden">
      <div className="flex items-center gap-3 flex-wrap px-4 py-3 bg-danger-500 border-b border-danger-500">
        <h2 className="font-mono text-sm text-canvas font-bold">{p.name}</h2>
        <div className="ml-auto flex items-center gap-2">
          <span className="font-mono text-2xs uppercase tracking-wider text-canvas border border-canvas px-1.5 py-0.5 squircle-md">
            blocked
          </span>
          <Button variant="normal" size="sm" onClick={approve} disabled={busy}>
            {busy ? "Approving…" : "Approve"}
          </Button>
        </div>
      </div>
      <div className="px-4 py-3 space-y-3">
        <Field label="Source">
          <span className="font-mono text-xs text-text-muted break-all">{p.source}</span>
        </Field>
        <Field label="Reason">
          <span className="text-xs text-danger-500">{p.reason}</span>
        </Field>
        {p.requested && (
          <Field label="Requires">
            <div className="flex flex-col gap-1">
              <div className="flex items-center gap-2 flex-wrap">
                {p.requested.version && (
                  <span className="font-mono text-2xs text-text-muted">{p.requested.version}</span>
                )}
                <NetworkBadge network={p.requested.network} />
                {p.requested.privileged && <PrivilegedBadge />}
              </div>
              <RequestedTypes label="egress" items={p.requested.egress} />
              <RequestedTypes label="credentials" items={p.requested.credentials} />
              <RequestedTypes label="endpoints" items={p.requested.endpoints} />
              <RequestedTypes label="tunnels" items={p.requested.tunnels} />
              <RequestedTypes label="facets" items={p.requested.facets} />
            </div>
          </Field>
        )}
        <Field label="Or run">
          <code className="font-mono text-2xs text-text bg-navy-100 px-2 py-1 squircle-md break-all">
            clawpatrol plugins approve &lt;config.hcl&gt; {p.name}
          </code>
        </Field>
        {err && <div className="text-xs text-danger-500">{err}</div>}
      </div>
    </section>
  );
}

function PluginCard({ p }: { p: Plugin }) {
  return (
    <section className="bg-canvas border-1.5 border-navy overflow-hidden">
      <div className="flex items-center gap-3 flex-wrap px-4 py-3 bg-navy-100 border-b border-navy">
        <h2 className="font-mono text-sm text-navy font-bold">{p.name}</h2>
        {p.version && <span className="font-mono text-2xs text-text-muted">v{p.version}</span>}
        <div className="ml-auto flex items-center gap-2">
          <NetworkBadge network={p.network ?? "none"} />
          <SandboxBadge mode={p.sandboxMode ?? ""} />
        </div>
      </div>

      {p.sandboxWarning && (
        <div className="px-4 py-2 bg-butter-100 border-b border-butter-300 text-xs text-rust-700">
          Reduced sandbox: {p.sandboxWarning}
        </div>
      )}

      {p.updateAvailable && (
        <div className="px-4 py-2 bg-navy-100 border-b border-navy text-xs text-navy">
          Update available: <span className="font-mono font-bold">{p.updateAvailable}</span> — run{" "}
          <code className="font-mono text-2xs bg-canvas px-1 py-0.5 squircle-md">
            clawpatrol plugins update
          </code>
        </div>
      )}

      <div className="px-4 py-3 space-y-3">
        <Field label="Source">
          <span className="font-mono text-xs text-text-muted break-all">{p.source}</span>
        </Field>
        {p.approvedHashes && p.approvedHashes.length > 0 && (
          <Field label="Approved">
            <div className="flex flex-col gap-0.5">
              {p.approvedHashes.map((h) => (
                <span key={h} className="font-mono text-2xs text-text-muted break-all">
                  {h}
                </span>
              ))}
            </div>
          </Field>
        )}
        <TypeGroup label="Egress" items={p.egress} />
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

function RequestedTypes({ label, items }: { label: string; items?: string[] }) {
  if (!items || items.length === 0) return null;
  return (
    <div className="flex items-baseline gap-2 flex-wrap">
      <span className="font-mono text-2xs text-text-muted">{label}:</span>
      {items.map((t) => (
        <span
          key={t}
          className="font-mono text-2xs text-navy bg-navy-100 px-1.5 py-0.5 squircle-md"
        >
          {t}
        </span>
      ))}
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

function PrivilegedBadge() {
  return (
    <Badge
      tone="danger"
      title="Privileged — the plugin needs to run with the sandbox OFF (full host access). Approve only if you trust it."
    >
      privileged
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
