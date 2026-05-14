// Settings page — replaces the floating SettingsModal. Credentials
// declared in gateway.hcl are rendered at the top; the gateway.hcl
// editor sits below. Both sections existed before — this is purely a
// UI reorganisation from "modal popped over whatever the user was
// looking at" to "real routed page".

import { useEffect, useState } from "react";
import {
  getConfigHCL,
  previewConfigHCL,
  saveConfigHCL,
  type ConfigSavePreview,
  type Integration,
} from "../lib/api";
import { Button } from "./Button";
import { ConfigSaveReview } from "./ConfigSaveReview";
import { HCLEditor } from "./HCLEditor";
import { IntegrationsCards } from "./IntegrationsCards";

export function SettingsPage({
  integrations,
  readOnlyConfig,
  onConnect,
  onRefresh,
}: {
  integrations: Integration[];
  readOnlyConfig?: boolean;
  onConnect: (id: string) => void;
  onRefresh: () => void;
}) {
  return (
    <main className="mx-auto w-full max-w-[1100px] px-4 sm:px-6 py-5 space-y-6">
      <nav className="text-sm text-text-subtle flex items-center gap-1.5">
        <a href="#/" className="hover:text-text">
          clawpatrol
        </a>
        <span>/</span>
        <span className="text-text-muted">settings</span>
      </nav>

      <section className="space-y-3">
        <h2 className="text-xs uppercase tracking-[.12em] text-navy font-bold">CREDENTIALS</h2>
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

      <ConfigSection readOnly={readOnlyConfig} onSaved={onRefresh} />
    </main>
  );
}

function ConfigSection({ readOnly, onSaved }: { readOnly?: boolean; onSaved: () => void }) {
  const [text, setText] = useState("");
  const [original, setOriginal] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [okMsg, setOkMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<ConfigSavePreview | null>(null);

  useEffect(() => {
    getConfigHCL()
      .then((t) => {
        setText(t);
        setOriginal(t);
      })
      .catch((e: Error) => setErr(String(e.message ?? e)));
  }, []);

  async function save() {
    setBusy(true);
    setErr(null);
    setOkMsg(null);
    try {
      const p = await previewConfigHCL(text);
      setPreview(p);
    } catch (e: any) {
      setErr(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  }

  async function confirmSave(confirmHighRisk: boolean) {
    if (!preview) return;
    setBusy(true);
    setErr(null);
    setOkMsg(null);
    try {
      const r = await saveConfigHCL(
        preview.formatted,
        preview.revision,
        preview.preview_token,
        confirmHighRisk,
      );
      setText(preview.formatted);
      setOriginal(preview.formatted);
      setPreview(null);
      setOkMsg(`saved · ${r.bytes} bytes`);
      onSaved();
    } catch (e: any) {
      setPreview(null);
      setErr(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  }

  const dirty = text !== original;

  return (
    <section className="space-y-3">
      <div className="bg-canvas-light border-2 border-navy overflow-hidden">
        <div className="flex items-center px-4 py-3 bg-navy-100">
          <h2 className="text-xs uppercase tracking-[.12em] text-navy font-bold">
            CONFIGURATION · gateway.hcl
            {readOnly && (
              <span className="ml-2 normal-case tracking-normal font-normal text-navy/70">
                · read-only (--read-only-config)
              </span>
            )}
          </h2>
        </div>
        <div className="overflow-auto">
          <HCLEditor value={text} onChange={setText} minHeight={420} readOnly={readOnly} />
        </div>
        <div className="flex items-center gap-2 px-4 py-3 border-t border-canvas-dark">
          {err && <div className="text-xs text-danger-500 truncate">{err}</div>}
          {okMsg && <div className="text-xs text-success-600 truncate">{okMsg}</div>}
          {!readOnly && (
            <Button onClick={save} disabled={!dirty || busy} className="ml-auto">
              {busy ? "saving…" : "save"}
            </Button>
          )}
        </div>
      </div>
      {preview && (
        <ConfigSaveReview
          preview={preview}
          busy={busy}
          onCancel={() => setPreview(null)}
          onConfirm={confirmSave}
        />
      )}
    </section>
  );
}
