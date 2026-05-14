import { useEffect, useState } from "react";
import {
  aiEditRules,
  getConfigHCL,
  previewConfigHCL,
  saveConfigHCL,
  type ConfigSavePreview,
} from "../lib/api";
import { Button } from "./Button";
import { ConfigSaveReview } from "./ConfigSaveReview";
import { HCLEditor } from "./HCLEditor";
import { Modal } from "./Modal";

// RulesEditor edits the whole gateway.hcl file. Validation runs
// server-side; diagnostics surface in the err panel.
export function RulesEditor({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [text, setText] = useState("");
  const [original, setOriginal] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [okMsg, setOkMsg] = useState<string | null>(null);
  const [preview, setPreview] = useState<ConfigSavePreview | null>(null);
  const [aiPrompt, setAIPrompt] = useState("");
  const [aiBusy, setAIBusy] = useState(false);

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

  async function runAI(e: React.FormEvent) {
    e.preventDefault();
    if (!aiPrompt.trim()) return;
    setAIBusy(true);
    setErr(null);
    try {
      const r = await aiEditRules(aiPrompt, text, "global");
      if (r.refused) {
        setErr("AI declined: " + r.refused);
      } else if (r.yaml) {
        setText(r.yaml);
      }
      setAIPrompt("");
    } catch (e: any) {
      setErr(String(e.message ?? e));
    } finally {
      setAIBusy(false);
    }
  }

  const dirty = text !== original;

  return (
    <>
      <Modal size="lg" title="Edit gateway.hcl" onClose={onClose}>
        <div className="flex-1 overflow-auto">
          <HCLEditor value={text} onChange={setText} minHeight={320} />
        </div>

        <form
          onSubmit={runAI}
          className="flex items-center gap-2 px-4 py-2.5 border-t border-navy bg-canvas"
        >
          <span className="text-2xs uppercase tracking-wider text-text-subtle">AI</span>
          <input
            type="text"
            value={aiPrompt}
            onChange={(e) => setAIPrompt(e.target.value)}
            placeholder='e.g. "deny POSTs to api.github.com" — uses connected Claude/Codex'
            className="flex-1 text-xs border border-canvas-dark rounded px-2 py-1.5 focus:outline-none focus:border-text transition-colors"
          />
          <Button type="submit" variant="outline" disabled={aiBusy || !aiPrompt.trim()}>
            {aiBusy ? "thinking…" : "apply"}
          </Button>
        </form>

        <div className="flex items-center px-4 py-3 border-t border-navy gap-3">
          {err && <span className="text-xs text-rust-700 break-all flex-1">{err}</span>}
          {okMsg && <span className="text-xs text-success-600 flex-1">{okMsg}</span>}
          {!err && !okMsg && (
            <span className="text-xs text-text-subtle flex-1">
              {dirty ? "unsaved changes" : "no changes"}
            </span>
          )}
          <Button variant="outline" onClick={onClose}>
            close
          </Button>
          <Button onClick={save} disabled={!dirty || busy}>
            {busy ? "saving…" : "save"}
          </Button>
        </div>
      </Modal>
      {preview && (
        <ConfigSaveReview
          preview={preview}
          busy={busy}
          onCancel={() => setPreview(null)}
          onConfirm={confirmSave}
        />
      )}
    </>
  );
}
