// Settings page. Credentials declared in gateway.hcl render at the
// top; the gateway.hcl viewer below shows the running config in
// read-only mode. The gateway no longer accepts dashboard-driven
// config edits — operators push HCL via SSH from a separate repo.

import { useEffect, useState } from "react";
import { getConfigHCL, type Integration } from "../lib/api";
import { HCLEditor } from "./HCLEditor";
import { IntegrationsCards } from "./IntegrationsCards";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";

export function SettingsPage({
  integrations,
  onConnect,
  onRefresh,
}: {
  integrations: Integration[];
  onConnect: (id: string) => void;
  onRefresh: () => void;
}) {
  return (
    <Main>
      <PageTitle trail={[{ label: "clawpatrol", href: "#/" }, { label: "settings" }]} />

      <section className="space-y-3">
        <h2 className="text-xs uppercase tracking-wider text-navy font-bold">Credentials</h2>
        {integrations.length === 0 ? (
          <div className="bg-canvas-light border-2 border-navy px-4 py-6 text-xs text-text-subtle">
            No credentials declared in gateway.hcl yet. Add a credential block to connect Anthropic
            / GitHub / Notion / Postgres / etc. here.
          </div>
        ) : (
          <IntegrationsCards
            list={integrations}
            showAll
            onConnect={onConnect}
            onRefresh={onRefresh}
          />
        )}
      </section>

      <ConfigSection />
    </Main>
  );
}

function ConfigSection() {
  const [text, setText] = useState("");
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getConfigHCL()
      .then(setText)
      .catch((e: Error) => setErr(String(e.message ?? e)));
  }, []);

  return (
    <section className="space-y-3">
      <div className="bg-canvas-light border-2 border-navy overflow-hidden">
        <div className="flex items-center px-4 py-3 bg-navy-100 border-b border-navy">
          <h2 className="text-xs uppercase tracking-wider text-navy font-bold">
            Configuration · gateway.hcl
            <span className="ml-2 normal-case tracking-normal font-normal text-navy/70">
              · read-only (push edits via your config repo)
            </span>
          </h2>
        </div>
        <div className="overflow-auto">
          <HCLEditor value={text} onChange={() => {}} minHeight={420} readOnly />
        </div>
        {err && (
          <div className="flex items-center gap-2 px-4 py-3 border-t border-navy">
            <div className="text-xs text-danger-500 truncate">{err}</div>
          </div>
        )}
      </div>
    </section>
  );
}
