import { useState } from "react";
import type { Integration } from "../lib/api";
import { setCredentialSlots } from "../lib/api";

// Modal that renders one input per declared SecretSlot for a non-OAuth
// credential. Single-slot credentials (bearer / header / cookie / api
// key) get one input; multi-slot (mtls cert+key+ca, slack bot+app)
// get one input per slot. PEM-shaped slots use a textarea.
//
// On Save, all filled slots are PUT through /api/credentials/set.
// Empty slots clear that one slot. Doesn't fetch existing values
// (we never read raw secrets back to the browser); operator
// re-pastes when rotating.
export function CredentialSecretsModal({
  integration,
  onClose,
  onSaved,
}: {
  integration: Integration;
  onClose: () => void;
  onSaved: () => void;
}) {
  const slots = integration.slots ?? [];
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
          <div className="text-[14px] font-semibold text-[#171717]">Connect {integration.name}</div>
          <button
            onClick={onClose}
            className="text-[#a3a3a3] hover:text-[#171717] text-[14px] leading-none"
          >
            ✕
          </button>
        </div>
        <div className="flex flex-col gap-3">
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
              {saving ? "Saving…" : "Save"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
