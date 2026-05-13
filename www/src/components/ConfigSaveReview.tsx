import { useMemo } from "react";
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
  onConfirm: () => void;
}) {
  const diffHtml = useMemo(
    () => highlightDiff(preview.diff || "No file content changes after formatting."),
    [preview.diff],
  );

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
          <Button onClick={onConfirm} disabled={busy || !preview.changed}>
            {busy ? "saving…" : "save changes"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
