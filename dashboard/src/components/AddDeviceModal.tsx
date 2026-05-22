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
    <Modal title="Add device" onClose={onClose}>
      <div className="p-4 space-y-6">
        <h3 className="text-sm leading-none tracking-tight text-text font-mono">
          Run the following on the new device:
        </h3>
        <Step n={1} label="Install" cmd={installCmd} />
        <Step n={2} label="Join" cmd={joinCmd} />
      </div>
    </Modal>
  );
}

function Step({ n, label, cmd }: { n: number; label: string; cmd: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    const flash = () => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    };
    try {
      await navigator.clipboard.writeText(cmd);
      flash();
      return;
    } catch {
      // Fall through to the legacy path below. Reasons writeText can
      // throw: non-secure context, page not focused, browser policy.
    }
    const ta = document.createElement("textarea");
    ta.value = cmd;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try {
      if (document.execCommand("copy")) flash();
    } finally {
      document.body.removeChild(ta);
    }
  }
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2">
        <span className="w-6 h-6 squircle-md bg-navy-100 text-xs font-semibold font-mono flex items-center justify-center shrink-0">
          {n}
        </span>
        <span className="text-sm text-text-muted font-sans">{label}</span>
      </div>
      <div className="relative">
        <pre className="bg-navy rounded px-4 py-4 text-xs font-mono text-canvas overflow-x-auto whitespace-pre">
          {cmd}
        </pre>
        <Button variant="outline" onClick={copy} className="absolute top-2.5 right-1">
          {copied ? "copied" : "copy"}
        </Button>
      </div>
    </div>
  );
}
