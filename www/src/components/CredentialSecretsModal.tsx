import { useState } from "react";
import type { Integration } from "../lib/api";
import { setCredentialSlots } from "../lib/api";
import { credentialTypeLabel } from "../lib/credentialLabels";

// Modal that renders one input per declared SecretSlot for a non-OAuth
// credential. Single-slot credentials (bearer / header / cookie / api
// key) get one input; multi-slot (mtls cert+key+ca, slack bot+app)
// get one input per slot. PEM-shaped slots use a textarea.
//
// On Save, touched slots are PUT through /api/credentials/set.
// Empty touched slots clear that one slot. Untouched slots are omitted,
// and existing values are never fetched back into the browser.
export function CredentialSecretsModal({
  integration,
  mode = "connect",
  onClose,
  onSaved,
}: {
  integration: Integration;
  mode?: "connect" | "update";
  onClose: () => void;
  onSaved: () => void;
}) {
  const slots = integration.slots ?? [];
  const label = credentialTypeLabel(integration.type, integration.name);
  const [values, setValues] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function update(name: string, v: string) {
    setValues((s) => ({ ...s, [name]: v }));
  }

  async function save() {
    setSaving(true);
    setErr(null);
    try {
      await setCredentialSlots(integration.id, values);
      onSaved();
      onClose();
    } catch (e) {
      setErr(String(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/30"
      onClick={onClose}
    >
      <div
        className="bg-white border border-[#e5e5e5] rounded shadow-lg w-full max-w-md p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="text-[14px] font-semibold text-[#171717]">
              {mode === "update" ? "Update" : "Connect"} {label}
            </div>
            <div className="text-[11px] text-[#737373]">
              <span className="font-mono">{integration.id}</span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#a3a3a3] hover:text-[#171717] text-[14px] leading-none"
          >
            ✕
          </button>
        </div>
        <div className="flex flex-col gap-3">
          {mode === "update" && (
            <p className="text-[11px] leading-relaxed text-[#737373]">
              Existing secret values are not shown. Paste a new value to replace a slot; leave
              untouched slots blank to keep them unchanged.
            </p>
          )}
          <dl className="grid grid-cols-[auto,minmax(0,1fr)] gap-x-3 gap-y-1 rounded border border-[#e5e5e5] bg-[#fafafa] px-3 py-2 text-[11px]">
            <dt className="text-[#737373]">Credential</dt>
            <dd className="min-w-0 truncate font-mono text-[#171717]" title={integration.id}>
              {integration.id}
            </dd>
            <dt className="text-[#737373]">Type</dt>
            <dd className="min-w-0 truncate text-[#171717]" title={integration.type}>
              {label} <span className="font-mono text-[#737373]">({integration.type})</span>
            </dd>
          </dl>
          {slots.map((s) => (
            <label key={s.name} className="flex flex-col gap-1">
              <span className="text-[11px] uppercase tracking-[.08em] text-[#737373]">
                {s.label}
              </span>
              {s.multiline ? (
                <textarea
                  rows={5}
                  value={values[s.name] ?? ""}
                  onChange={(e) => update(s.name, e.target.value)}
                  placeholder={s.description ?? ""}
                  className="border border-[#e5e5e5] rounded px-2 py-1.5 text-[12px] font-mono focus:outline-none focus:border-[#171717]"
                />
              ) : (
                <input
                  type="password"
                  value={values[s.name] ?? ""}
                  onChange={(e) => update(s.name, e.target.value)}
                  placeholder={s.description ?? ""}
                  className="border border-[#e5e5e5] rounded px-2 py-1.5 text-[12px] focus:outline-none focus:border-[#171717]"
                />
              )}
              {s.description && !s.multiline && (
                <span className="text-[10px] text-[#a3a3a3]">{s.description}</span>
              )}
            </label>
          ))}
          {err && <div className="text-[11px] text-[#dc2626]">{err}</div>}
          <div className="flex justify-end gap-2 mt-2">
            <button
              onClick={onClose}
              className="text-[12px] px-3 py-1.5 border border-[#e5e5e5] text-[#737373] rounded hover:border-[#a3a3a3] hover:text-[#171717]"
            >
              Cancel
            </button>
            <button
              onClick={save}
              disabled={saving}
              className="text-[12px] px-3 py-1.5 bg-[#171717] text-white rounded hover:bg-[#404040] disabled:opacity-50"
            >
              {saving ? "Saving…" : mode === "update" ? "Update" : "Save"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
