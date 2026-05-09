// Global gateway settings — full gateway.hcl in a syntax-highlighted
// editor. Saving writes back to disk; the gateway's mtime watcher
// hot-reloads rules / profiles / approvers without a restart.

import { useEffect, useState } from "react";
import { getConfigHCL, putConfigHCL } from "../lib/api";
import { HCLEditor } from "./HCLEditor";

export function SettingsModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [text, setText] = useState("");
  const [original, setOriginal] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [okMsg, setOkMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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
            GATEWAY SETTINGS · gateway.hcl
          </div>
          <button
            onClick={onClose}
            className="ml-auto text-[11px] px-2 py-1 text-[#a3a3a3] hover:text-[#171717]"
          >
            ✕
          </button>
        </div>

        <div className="flex-1 overflow-auto">
          <HCLEditor value={text} onChange={setText} minHeight={420} />
        </div>

        <div className="flex items-center gap-2 px-4 py-3 border-t border-[#e5e5e5]">
          {err && <div className="text-[11px] text-red-600 truncate">{err}</div>}
          {okMsg && <div className="text-[11px] text-green-700 truncate">{okMsg}</div>}
          <button
            onClick={save}
            disabled={!dirty || busy}
            className="ml-auto text-[11px] px-3 py-1 bg-black text-white rounded disabled:opacity-40 hover:bg-[#171717]"
          >
            {busy ? "saving…" : "save"}
          </button>
        </div>
      </div>
    </div>
  );
}
