import { useEffect, useState } from "react";
import { getConfigHCL, type Integration } from "../../lib/api";
import { HCLEditor } from "../../components/HCLEditor";
import { IntegrationsCards } from "../../components/IntegrationsCards";
import { Card } from "../cards/Card";
import { PageHeader } from "../cards/PageHeader";

// Settings — credential connect/disconnect + HCL viewer.
// cl-r3e explicitly preserves the credential modals from cl-jli /
// cl-fq1 / cl-003 / cl-irg. We mount the existing IntegrationsCards
// + ConnectModal flow verbatim instead of porting unclaw's
// credential UX. The v1 Settings page does the same — this is
// really just a re-skin of that page inside the v2 shell.
export function V2SettingsPage({
  integrations,
  onConnect,
  onRefresh,
}: {
  integrations: Integration[];
  onConnect: (id: string) => void;
  onRefresh: () => void;
}) {
  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Settings"
        subhead="Credentials and the running gateway.hcl. Credential modals are the existing clawpatrol ones — connect / disconnect flows are unchanged."
      />

      <Card title="Credentials" count={integrations.length}>
        {integrations.length === 0 ? (
          <div className="py-2 text-sm text-text-muted">
            No credentials declared in gateway.hcl yet.
          </div>
        ) : (
          <IntegrationsCards
            list={integrations}
            showAll
            onConnect={onConnect}
            onRefresh={onRefresh}
          />
        )}
      </Card>

      <ConfigSection />
    </div>
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
    <Card title="Configuration · gateway.hcl">
      <div className="text-xs text-text-muted mb-2">
        Read-only. Push edits via your config repo.
      </div>
      <div className="overflow-auto border border-canvas-dark">
        <HCLEditor value={text} onChange={() => {}} minHeight={420} readOnly />
      </div>
      {err && <div className="mt-2 text-xs text-danger-700">{err}</div>}
    </Card>
  );
}
