import { useMemo } from "react";
import type { ConfigSavePreview } from "../lib/api";
import { highlightDiff } from "../lib/diffHighlight";

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
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-[60]">
      <div className="bg-white border border-[#e5e5e5] rounded-md shadow-2xl flex flex-col w-[920px] max-w-[96vw] max-h-[88vh]">
        <div className="flex items-center px-4 py-3 border-b border-[#e5e5e5]">
          <div>
            <div className="text-[11px] uppercase tracking-[.12em] text-[#a3a3a3]">
              REVIEW GATEWAY.HCL CHANGES
            </div>
            <div className="text-[12px] text-[#737373] mt-1">
              HCL parsed successfully · formatting applied · {preview.bytes} bytes will be saved
            </div>
          </div>
          <button
            onClick={onCancel}
            disabled={busy}
            className="ml-auto text-[11px] px-2 py-1 text-[#a3a3a3] hover:text-[#171717] disabled:opacity-40"
          >
            ✕
          </button>
        </div>

        <div className="px-4 py-3 border-b border-[#e5e5e5] bg-[#fafafa] text-[12px] text-[#404040]">
          Confirming writes the <span className="font-mono">formatted</span> config represented by
          the diff below to disk. If <span className="font-mono">gateway.hcl</span> changed since
          this preview, the save is rejected.
        </div>

        <pre className="config-diff-view flex-1 overflow-auto m-0 p-4 text-[12px] leading-5 font-mono whitespace-pre-wrap language-diff diff-highlight">
          <code
            className="config-diff-view language-diff diff-highlight"
            dangerouslySetInnerHTML={{ __html: diffHtml }}
          />
        </pre>

        <div className="flex items-center gap-2 px-4 py-3 border-t border-[#e5e5e5]">
          <button
            onClick={onCancel}
            disabled={busy}
            className="ml-auto text-[11px] px-3 py-1.5 border border-[#e5e5e5] text-[#737373] rounded hover:border-[#a3a3a3] disabled:opacity-40"
          >
            back to editor
          </button>
          <button
            onClick={onConfirm}
            disabled={busy || !preview.changed}
            className="text-[11px] px-3 py-1.5 border border-[#171717] text-white bg-[#171717] rounded hover:bg-[#262626] disabled:opacity-40"
          >
            {busy ? "saving…" : "save changes"}
          </button>
        </div>
      </div>
    </div>
  );
}
