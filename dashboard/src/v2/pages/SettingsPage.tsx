import { useEffect, useState } from "react";
import { getConfigHCL, type Integration } from "../../lib/api";
import { CredentialsTypeGrid } from "../../components/CredentialsTypeGrid";
import { HCLEditor } from "../../components/HCLEditor";
import { Card } from "../cards/Card";
import { PageHeader } from "../cards/PageHeader";

// Settings — credentials (per-type cards with an expanding details
// table) + read-only gateway.hcl viewer. The credentials section
// mirrors the v1 Settings page (CredentialsTypeGrid) — connect /
// disconnect / update flows are the existing clawpatrol ones.
export function V2SettingsPage({
  integrations,
  onConnect,
  onRefresh,
  pendingConnect,
  onConsumePendingConnect,
}: {
  integrations: Integration[];
  onConnect: (id: string) => void;
  onRefresh: () => void;
  // Set when navigated to via `#/v2/settings?connect=<id>` (the
  // Profiles page pills do this — clicking a pill should open the
  // same connect flow the settings cards drive).
  pendingConnect?: string;
  onConsumePendingConnect?: () => void;
}) {
  // Auto-open the connect modal for ?connect=<id> arrivals from the
  // Profiles page. CredentialsTypeGrid drives connect via its own
  // click handlers, so we fire onConnect once for the deep-linked id
  // and immediately drop the query string.
  useEffect(() => {
    if (!pendingConnect) return;
    if (!integrations.some((i) => i.id === pendingConnect)) return;
    onConnect(pendingConnect);
    onConsumePendingConnect?.();
  }, [pendingConnect, integrations, onConnect, onConsumePendingConnect]);

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
          <CredentialsTypeGrid list={integrations} onConnect={onConnect} onRefresh={onRefresh} />
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
