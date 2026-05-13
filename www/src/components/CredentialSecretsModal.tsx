import { useState } from "react";
import type { Integration } from "../lib/api";
import { setCredentialSlots } from "../lib/api";
import { credentialTypeLabel } from "../lib/credentialLabels";
import { Button } from "./Button";
import { Modal } from "./Modal";

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
    <Modal onClose={onClose} labelledBy="credential-modal-title">
      <div className="bg-canvas-light border-2 border-navy rounded shadow-lg overflow-hidden w-full max-w-md">
        <div className="flex items-center px-5 py-3 bg-navy-100">
          <h2
            id="credential-modal-title"
            className="text-xs uppercase tracking-[.12em] text-navy font-bold"
          >
            {mode === "update" ? "Update" : "Connect"} {label}
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="ml-auto text-xl leading-none px-2 py-1 text-navy hover:text-text"
          >
            ✕
          </button>
        </div>
        <div className="flex flex-col gap-3 p-5">
          {mode === "update" && (
            <p className="text-xs leading-relaxed text-text-muted">
              Existing secret values are not shown. Paste a new value to replace a slot; leave
              untouched slots blank to keep them unchanged.
            </p>
          )}
          <dl className="grid grid-cols-[auto,minmax(0,1fr)] gap-x-3 gap-y-1 rounded border border-canvas-dark bg-canvas-muted px-3 py-2 text-xs">
            <dt className="text-text-muted">Credential</dt>
            <dd className="min-w-0 truncate font-mono text-text" title={integration.id}>
              {integration.id}
            </dd>
            <dt className="text-text-muted">Type</dt>
            <dd className="min-w-0 truncate text-text" title={integration.type}>
              {label} <span className="font-mono text-text-muted">({integration.type})</span>
            </dd>
          </dl>
          {slots.map((s) => (
            <label key={s.name} className="flex flex-col gap-1">
              <span className="text-xs uppercase tracking-[.08em] text-text-muted">{s.label}</span>
              {s.multiline ? (
                <textarea
                  rows={5}
                  value={values[s.name] ?? ""}
                  onChange={(e) => update(s.name, e.target.value)}
                  placeholder={s.description ?? ""}
                  className="border border-canvas-dark rounded px-2 py-1.5 text-xs font-mono focus:outline-none focus:border-text"
                />
              ) : (
                <input
                  type="password"
                  value={values[s.name] ?? ""}
                  onChange={(e) => update(s.name, e.target.value)}
                  placeholder={s.description ?? ""}
                  className="border border-canvas-dark rounded px-2 py-1.5 text-xs focus:outline-none focus:border-text"
                />
              )}
              {s.description && !s.multiline && (
                <span className="text-2xs text-text-subtle">{s.description}</span>
              )}
            </label>
          ))}
          {err && <div className="text-xs text-danger-500">{err}</div>}
          <div className="flex justify-end gap-2 mt-2">
            <Button variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button onClick={save} disabled={saving}>
              {saving ? "Saving…" : mode === "update" ? "Update" : "Save"}
            </Button>
          </div>
        </div>
      </div>
    </Modal>
  );
}
