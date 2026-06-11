import { useEffect, useState } from "react";
import { listProfiles, type Whoami } from "../lib/api";
import { Button } from "./Button";
import { Modal } from "./Modal";
import { copyText } from "../lib/clipboard";

// shellArg quotes s for copy-paste into a POSIX shell when it
// contains anything beyond plain word characters.
function shellArg(s: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(s)) return s;
  return "'" + s.replaceAll("'", "'\\''") + "'";
}

export function AddDeviceModal({
  whoami,
  onClose,
}: {
  whoami?: Whoami | null;
  onClose: () => void;
}) {
  const url = whoami?.public_url || window.location.origin;
  const [profiles, setProfiles] = useState<string[]>([]);
  const [profile, setProfile] = useState("");
  // Per-process `clawpatrol run` is the default; --whole-machine
  // installs system Tailscale and routes all of the machine's network
  // traffic through clawpatrol.
  const [mode, setMode] = useState<"run" | "whole-machine">("run");

  useEffect(() => {
    listProfiles()
      .then((p) => {
        setProfiles(p);
        // Mirror the gateway's default-profile pick: "default" if it
        // exists, else the first profile in source order.
        setProfile(p.includes("default") ? "default" : (p[0] ?? ""));
      })
      .catch(() => setProfiles([]));
  }, []);

  // An operator authenticated over the tailnet can mint joins that
  // auto-approve: --login joins with their identity and the gateway's
  // operator gate accepts the self-approval. Password sessions can't
  // promise that, so the plain browser-approval join is suggested.
  const login = whoami?.auth_method === "tailscale";

  const installCmd = "curl -fsSL https://clawpatrol.dev/install.sh | sh";
  const joinCmd = [
    "clawpatrol",
    "join",
    ...(login ? ["--login"] : []),
    ...(mode === "whole-machine" ? ["--whole-machine"] : []),
    ...(profile ? ["--profile", shellArg(profile)] : []),
    url,
  ].join(" ");

  return (
    <Modal title="Add device" onClose={onClose}>
      <div className="p-4 space-y-5">
        <h3 className="text-sm leading-none tracking-tight text-text font-mono">
          Run the following on the new device:
        </h3>

        <div className="space-y-3">
          {profiles.length > 1 && (
            <label className="block space-y-1">
              <span className="text-xs text-text-muted font-sans">Profile</span>
              <select
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                className="w-full font-mono text-xs text-text bg-canvas border-1.5 border-navy px-2 py-1.5"
              >
                {profiles.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label className="block space-y-1">
            <span className="text-xs text-text-muted font-sans">Mode</span>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as "run" | "whole-machine")}
              className="w-full font-mono text-xs text-text bg-canvas border-1.5 border-navy px-2 py-1.5"
            >
              <option value="run">clawpatrol run (per-process, default)</option>
              <option value="whole-machine">
                --whole-machine (route all of this machine's traffic through clawpatrol)
              </option>
            </select>
          </label>
        </div>

        <Step n={1} label="Install" cmd={installCmd} />
        <Step
          n={2}
          label={login ? "Join (auto-approves via your tailnet identity)" : "Join"}
          cmd={joinCmd}
        />
      </div>
    </Modal>
  );
}

function Step({ n, label, cmd }: { n: number; label: string; cmd: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    if (await copyText(cmd)) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  }
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="w-6 h-6 squircle-md bg-navy-100 text-xs font-semibold font-mono flex items-center justify-center shrink-0">
            {n}
          </span>
          <span className="text-sm text-text-muted font-sans truncate">{label}</span>
        </div>
        <Button variant="outline" onClick={copy} className="shrink-0">
          {copied ? "copied" : "copy"}
        </Button>
      </div>
      <pre className="bg-navy rounded px-4 py-4 text-xs font-mono text-canvas overflow-x-auto whitespace-pre">
        {cmd}
      </pre>
    </div>
  );
}
