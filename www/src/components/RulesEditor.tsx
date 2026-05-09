import { useEffect, useState } from "react";
import { aiEditRules, getConfigHCL, putConfigHCL } from "../lib/api";
import { HCLEditor } from "./HCLEditor";

// RulesEditor edits the whole gateway.hcl file. Validation runs
// server-side; diagnostics surface in the err panel.
export function RulesEditor({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [text, setText] = useState("");
  const [original, setOriginal] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [okMsg, setOkMsg] = useState<string | null>(null);
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
      const r = await putConfigHCL(text);
      setOkMsg(`saved · ${r.bytes} bytes`);
      setOriginal(text);
      onSaved();
    } catch (e: any) {
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
    <div
      className="fixed inset-0 bg-black/30 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <div
        className="bg-white border border-[#e5e5e5] rounded-md shadow-2xl flex flex-col w-[820px] max-w-full max-h-[85vh]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center px-4 py-3 border-b border-[#e5e5e5]">
          <div className="text-[11px] uppercase tracking-[.12em] text-[#a3a3a3]">
            EDIT GATEWAY.HCL
          </div>
          <button
            onClick={onClose}
            className="ml-auto text-[11px] px-2 py-1 text-[#a3a3a3] hover:text-[#171717]"
          >
            ✕
          </button>
        </div>

        <div className="flex-1 overflow-auto">
          <HCLEditor value={text} onChange={setText} minHeight={320} />
        </div>

        <form
          onSubmit={runAI}
          className="flex items-center gap-2 px-4 py-2.5 border-t border-[#e5e5e5] bg-white"
        >
          <span className="text-[10px] uppercase tracking-[.09em] text-[#a3a3a3]">AI</span>
          <input
            type="text"
            value={aiPrompt}
            onChange={(e) => setAIPrompt(e.target.value)}
            placeholder='e.g. "deny POSTs to api.github.com" — uses connected Claude/Codex'
            className="flex-1 text-[12px] border border-[#e5e5e5] rounded px-2 py-1.5 focus:outline-none focus:border-[#171717] transition-colors"
          />
          <button
            type="submit"
            disabled={aiBusy || !aiPrompt.trim()}
            className="text-[11px] px-3 py-1.5 border border-[#171717] text-[#171717] rounded hover:bg-[#171717] hover:text-white disabled:opacity-40"
          >
            {aiBusy ? "thinking…" : "apply"}
          </button>
        </form>

        <div className="flex items-center px-4 py-3 border-t border-[#e5e5e5] gap-3">
          {err && <span className="text-[11px] text-red-600 break-all flex-1">{err}</span>}
          {okMsg && <span className="text-[11px] text-[#16a34a] flex-1">{okMsg}</span>}
          {!err && !okMsg && (
            <span className="text-[11px] text-[#a3a3a3] flex-1">
              {dirty ? "unsaved changes" : "no changes"}
            </span>
          )}
          <button
            onClick={onClose}
            className="text-[11px] px-3 py-1.5 border border-[#e5e5e5] text-[#737373] rounded hover:border-[#a3a3a3]"
          >
            close
          </button>
          <button
            onClick={save}
            disabled={!dirty || busy}
            className="text-[11px] px-3 py-1.5 border border-[#171717] text-white bg-[#171717] rounded hover:bg-[#262626] disabled:opacity-40"
          >
            {busy ? "saving…" : "save"}
          </button>
        </div>
      </div>
    </div>
  );
}
