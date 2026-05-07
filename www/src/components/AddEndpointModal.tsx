import { useState } from "react";
import { addEndpoint } from "../lib/api";
import { HCLEditor } from "./HCLEditor";

// Small modal for "add an endpoint of type X to gateway.hcl". Shows
// only the starter snippet, not the whole file. The operator edits
// the names / hosts / referenced credential here, hits save, and the
// server appends the snippet AND splices the new endpoint name(s)
// into `profile`'s endpoints list — so the new endpoint actually
// applies to the device's traffic instead of dangling unbound.
//
// Server-side LoadBytes validates the merged file before persisting,
// so a typo still surfaces with gateway.hcl line numbers.
export function AddEndpointModal({
  type,
  initialHCL,
  profile,
  onClose,
  onSaved,
}: {
  type: string;
  initialHCL: string;
  profile?: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [text, setText] = useState(initialHCL);
  const [attach, setAttach] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function save() {
    setBusy(true);
    setErr(null);
    try {
      await addEndpoint(text, attach ? profile : undefined);
      onSaved();
    } catch (e: any) {
      setErr(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 bg-black/30 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <div
        className="bg-white border border-[#e5e5e5] rounded-md shadow-2xl flex flex-col w-[640px] max-w-full max-h-[85vh]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center px-4 py-3 border-b border-[#e5e5e5]">
          <div className="text-[11px] uppercase tracking-[.12em] text-[#a3a3a3]">
            ADD {type.toUpperCase()} ENDPOINT
          </div>
          <button
            onClick={onClose}
            className="ml-auto text-[11px] px-2 py-1 text-[#a3a3a3] hover:text-[#171717]"
          >
            ✕
          </button>
        </div>

        <div className="px-4 pt-3 pb-1 text-[11px] text-[#737373]">
          Edit the names, hosts, and referenced credential, then save —
          this snippet is appended to <code>gateway.hcl</code>.
        </div>

        <div className="flex-1 overflow-auto px-2">
          <HCLEditor value={text} onChange={setText} minHeight={220} />
        </div>

        {profile && (
          <label className="flex items-center gap-2 px-4 py-2 border-t border-[#e5e5e5] text-[11px] text-[#525252] cursor-pointer">
            <input
              type="checkbox"
              checked={attach}
              onChange={(e) => setAttach(e.target.checked)}
              className="cursor-pointer"
            />
            <span>
              Add the new endpoint to profile{" "}
              <span className="font-mono text-[#171717]">{profile}</span>
            </span>
          </label>
        )}

        <div className="flex items-center px-4 py-3 border-t border-[#e5e5e5] gap-3">
          {err && (
            <span className="text-[11px] text-red-600 break-all flex-1">{err}</span>
          )}
          {!err && (
            <span className="text-[11px] text-[#a3a3a3] flex-1">
              appended to gateway.hcl on save
            </span>
          )}
          <button
            onClick={onClose}
            className="text-[11px] px-3 py-1.5 border border-[#e5e5e5] text-[#737373] rounded hover:border-[#a3a3a3]"
          >
            cancel
          </button>
          <button
            onClick={save}
            disabled={busy || !text.trim()}
            className="text-[11px] px-3 py-1.5 border border-[#171717] text-white bg-[#171717] rounded hover:bg-[#262626] disabled:opacity-40"
          >
            {busy ? "saving…" : "append + save"}
          </button>
        </div>
      </div>
    </div>
  );
}
