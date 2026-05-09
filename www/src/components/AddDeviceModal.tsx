import { useState } from "react";

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
    <div
      className="fixed inset-0 bg-black/30 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <div
        className="bg-white border border-[#e5e5e5] rounded-md p-4 w-[600px] shadow-2xl space-y-3"
        onClick={(e) => e.stopPropagation()}
      >
        <div>
          <div className="text-[11px] uppercase tracking-[.12em] text-[#a3a3a3]">add device</div>
          <h2 className="font-serif text-[22px] leading-none tracking-tight text-[#171717] mt-1">
            run on the new machine
          </h2>
        </div>

        <Step n={1} label="install" cmd={installCmd} />
        <Step n={2} label="join" cmd={joinCmd} />
      </div>
    </div>
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
        <span className="w-[16px] h-[16px] rounded-full bg-[#171717] text-white text-[10px] font-semibold flex items-center justify-center flex-shrink-0">
          {n}
        </span>
        <span className="text-[11px] text-[#525252]">{label}</span>
      </div>
      <div className="relative">
        <pre className="bg-[#fafafa] border border-[#e5e5e5] rounded px-2.5 py-1.5 text-[12px] font-mono text-[#171717] overflow-x-auto whitespace-pre">
          {cmd}
        </pre>
        <button
          onClick={copy}
          className="absolute top-1 right-1 text-[10px] uppercase tracking-[.09em] px-1.5 py-0.5 bg-white border border-[#e5e5e5] rounded text-[#525252] hover:text-[#171717] hover:border-[#171717]"
        >
          {copied ? "copied" : "copy"}
        </button>
      </div>
    </div>
  );
}
