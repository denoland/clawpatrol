import { CrtDisplay } from "./CrtDisplay";

export function TerminalBlock() {
  return (
    <CrtDisplay title="terminal">
      <div class="crt-boot">
        <div
          class="px-6 sm:px-8 py-12 md:py-16 md:pb-20 text-sm space-y-1 font-mono"
          style={{
            textShadow:
              "0 0 6px color-mix(in srgb, var(--color-crt) 31%, transparent), 0 0 14px color-mix(in srgb, var(--color-crt-dim) 19%, transparent)",
          }}
        >
          <div class="whitespace-pre-wrap break-all">
            <span class="text-crt">curl -fsSL clawpatrol.dev/install.sh | sh</span>
          </div>
        </div>
      </div>
    </CrtDisplay>
  );
}
