// Settings page — replaces the floating SettingsModal. OAuth
// integrations are rendered at the top (canonical "connect Claude /
// GitHub / Notion / …" surface); the gateway.hcl editor sits below.
// Both sections existed before — this is purely a UI reorganisation
// from "modal popped over whatever the user was looking at" to "real
// routed page".

import { useEffect, useState } from "react";
import {
  getConfigHCL,
  previewConfigHCL,
  saveConfigHCL,
  type ConfigSavePreview,
  type Integration,
  type Whoami,
} from "../lib/api";
import { ConfigSaveReview } from "./ConfigSaveReview";
import { HCLEditor } from "./HCLEditor";
import { IntegrationsCards } from "./IntegrationsCards";

export function SettingsPage({
  integrations,
  whoami,
  readOnlyConfig,
  onConnect,
  onRefresh,
}: {
  integrations: Integration[];
  whoami: Whoami | null;
  readOnlyConfig?: boolean;
  onConnect: (id: string, profile?: string) => void;
  onRefresh: () => void;
}) {
  const oauthIntegrations = integrations.filter((i) => i.has_oauth);

  return (
    <main className="mx-auto w-full max-w-[1100px] px-4 sm:px-6 py-5 space-y-6">
      <nav className="text-[13px] text-[#a3a3a3] flex items-center gap-1.5">
        <a href="#/" className="hover:text-[#171717]">
          clawpatrol
        </a>
        <span>/</span>
        <span className="text-[#525252]">settings</span>
      </nav>

      <section className="space-y-3">
        <div className="text-[11px] uppercase tracking-[.12em] text-[#a3a3a3]">INTEGRATIONS</div>
        {oauthIntegrations.length === 0 ? (
          <div className="bg-white border border-[#e5e5e5] rounded px-4 py-6 text-[12px] text-[#a3a3a3]">
            No OAuth integrations declared in gateway.hcl yet. Add a credential block whose plugin
            advertises an OAuth flow to connect Anthropic / GitHub / Notion / etc. here.
          </div>
        ) : (
          <IntegrationsCards
            list={oauthIntegrations}
            whoami={whoami}
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

  async function confirmSave() {
    if (!preview) return;
    setBusy(true);
    setErr(null);
    setOkMsg(null);
    try {
      const r = await saveConfigHCL(preview.formatted, preview.revision, preview.preview_token);
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
      <div className="text-[11px] uppercase tracking-[.12em] text-[#a3a3a3]">
        CONFIGURATION · gateway.hcl
        {readOnly && (
          <span className="ml-2 normal-case tracking-normal text-[#737373]">
            · read-only (--read-only-config)
          </span>
        )}
      </div>
      <div className="bg-white border border-[#e5e5e5] rounded-md overflow-hidden">
        <div className="overflow-auto">
          <HCLEditor value={text} onChange={setText} minHeight={420} readOnly={readOnly} />
        </div>
        <div className="flex items-center gap-2 px-4 py-3 border-t border-[#e5e5e5]">
          {err && <div className="text-[11px] text-red-600 truncate">{err}</div>}
          {okMsg && <div className="text-[11px] text-green-700 truncate">{okMsg}</div>}
          {!readOnly && (
            <button
              onClick={save}
              disabled={!dirty || busy}
              className="ml-auto text-[11px] px-3 py-1 bg-black text-white rounded disabled:opacity-40 hover:bg-[#171717]"
            >
              {busy ? "saving…" : "save"}
            </button>
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
