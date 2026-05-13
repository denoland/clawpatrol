import { useState } from "react";
import { Button } from "./Button";
import { Modal } from "./Modal";

export function AddDeviceModal({
  publicURL,
  onClose,
}: {
  publicURL?: string;
  onClose: () => void;
}) {
  const url = publicURL || window.location.origin;
  const installCmd = "curl -fsSL https://clawpatrol.dev/install.sh | sh";
  const joinCmd = `clawpatrol join ${url}`;

  return (
    <Modal onClose={onClose} labelledBy="add-device-title">
      <div className="bg-canvas-light border-2 border-navy rounded-md shadow-2xl overflow-hidden w-[600px]">
        <div className="flex items-center px-4 py-3 bg-navy-100">
          <h2
            id="add-device-title"
            className="text-xs uppercase tracking-[.12em] text-navy font-bold"
          >
            ADD DEVICE
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
        <div className="p-4 space-y-6">
          <h3 className="font-serif text-2xl leading-none tracking-tight text-text">
            run on the new machine
          </h3>
          <Step n={1} label="install" cmd={installCmd} />
          <Step n={2} label="join" cmd={joinCmd} />
        </div>
      </div>
    </Modal>
  );
}

function Step({ n, label, cmd }: { n: number; label: string; cmd: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    navigator.clipboard.writeText(cmd).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2">
        <span className="w-[16px] h-[16px] rounded-full bg-navy text-canvas text-2xs font-semibold flex items-center justify-center shrink-0">
          {n}
        </span>
        <span className="text-xs text-text-muted">{label}</span>
      </div>
      <div className="relative">
        <pre className="bg-navy rounded px-4 py-3 text-xs font-mono text-canvas overflow-x-auto whitespace-pre">
          {cmd}
        </pre>
        <Button variant="outline" onClick={copy} className="absolute top-1 right-1">
          {copied ? "copied" : "copy"}
        </Button>
      </div>
    </div>
  );
}
