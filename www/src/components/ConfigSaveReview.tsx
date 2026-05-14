import { useMemo, useState } from "react";
import type { ConfigSavePreview } from "../lib/api";
import { highlightDiff } from "../lib/diffHighlight";
import { Button } from "./Button";
import { Modal } from "./Modal";

export function ConfigSaveReview({
  preview,
  busy,
  onCancel,
  onConfirm,
}: {
  preview: ConfigSavePreview;
  busy: boolean;
  onCancel: () => void;
  onConfirm: (confirmHighRisk: boolean) => void;
}) {
  const diffHtml = useMemo(
    () => highlightDiff(preview.diff || "No file content changes after formatting."),
    [preview.diff],
  );

  const highRisk = preview.high_risk_additions ?? [];
  const needsConfirm = highRisk.length > 0;
  const [confirmText, setConfirmText] = useState("");
  const confirmed = !needsConfirm || confirmText.trim().toLowerCase() === "confirm";

  return (
    <Modal onClose={onCancel} labelledBy="config-save-review-title">
      <div className="bg-canvas-light border-2 border-navy rounded-md shadow-2xl overflow-hidden flex flex-col w-[920px] max-w-[96vw] max-h-[88vh]">
        <div className="flex items-center px-4 py-3 bg-navy-100">
          <div>
            <h2
              id="config-save-review-title"
              className="text-xs uppercase tracking-[.12em] text-navy font-bold"
            >
              REVIEW GATEWAY.HCL CHANGES
            </h2>
            <div className="text-xs text-navy/70 mt-1">
              HCL parsed successfully · formatting applied · {preview.bytes} bytes will be saved
            </div>
          </div>
          <button
            type="button"
            onClick={onCancel}
            disabled={busy}
            aria-label="Close"
            className="ml-auto text-xl leading-none px-2 py-1 text-navy hover:text-text disabled:opacity-40"
          >
            ✕
          </button>
        </div>

        {needsConfirm && (
          <div className="px-4 py-3 border-b-2 border-danger-500 bg-danger-50 text-xs text-text">
            <div className="font-bold text-danger-600 uppercase tracking-[.09em] mb-1">
              High-risk change · process spawn
            </div>
            <div className="mb-2">
              This draft adds new <span className="font-mono">tunnel "local_command"</span>{" "}
              block(s), which run arbitrary OS commands on the gateway host whenever traffic routes
              through them:
            </div>
            <ul className="list-disc list-inside font-mono text-2xs space-y-0.5 mb-2">
              {highRisk.map((name) => (
                <li key={name}>{name}</li>
              ))}
            </ul>
            <div className="mb-2">
              Confirm only if you intend to grant the gateway service user that execution privilege.
              Type <span className="font-mono font-bold">confirm</span> to enable save:
            </div>
            <input
              type="text"
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              disabled={busy}
              autoFocus
              placeholder="confirm"
              className="px-2 py-1 border-2 border-navy bg-canvas font-mono text-xs w-40 focus:outline-none focus:border-danger-500"
            />
          </div>
        )}

        <div className="px-4 py-3 border-b border-canvas-dark bg-canvas-muted text-xs text-text">
          Confirming writes the <span className="font-mono">formatted</span> draft below to disk. If{" "}
          <span className="font-mono">gateway.hcl</span> changed since this preview, the save is
          rejected.
        </div>

        <pre className="config-diff-view flex-1 overflow-auto m-0 p-4 text-xs leading-5 font-mono whitespace-pre-wrap language-diff diff-highlight">
          <code
            className="config-diff-view language-diff diff-highlight"
            dangerouslySetInnerHTML={{ __html: diffHtml }}
          />
        </pre>

        <div className="flex items-center gap-2 px-4 py-3 border-t border-canvas-dark">
          <Button variant="outline" onClick={onCancel} disabled={busy} className="ml-auto">
            back to editor
          </Button>
          <Button
            onClick={() => onConfirm(needsConfirm)}
            disabled={busy || !preview.changed || !confirmed}
          >
            {busy ? "saving…" : needsConfirm ? "save (high-risk)" : "save changes"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
