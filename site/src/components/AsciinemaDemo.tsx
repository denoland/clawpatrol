import { useEffect, useRef } from "preact/hooks";

type AsciinemaPlayer = {
  dispose: () => void;
};

const playerOptions = {
  autoPlay: true,
  loop: true,
  controls: false,
  fit: "width",
  terminalFontFamily:
    '"IBM Plex Mono", "SFMono-Regular", Consolas, "Liberation Mono", monospace',
  terminalFontSize: 14,
  terminalLineHeight: 1.25,
  theme: "monokai",
  idleTimeLimit: 1.2,
  poster: "npt:0",
};

export function AsciinemaDemo() {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let player: AsciinemaPlayer | undefined;
    let cancelled = false;

    async function mountPlayer() {
      const container = containerRef.current;
      if (!container) return;

      const { create } = await import("asciinema-player");
      if (cancelled) return;

      player = create("/clawpatrol-demo.cast", container, playerOptions);
    }

    mountPlayer();

    return () => {
      cancelled = true;
      player?.dispose();
    };
  }, []);

  return (
    <div
      class="asciinema-hero w-full md:max-w-[92%] border border-navy squircle-lg shadow-[4px_6px_0_0_var(--color-canvas-300)] overflow-hidden bg-[#121314]"
      aria-label="Claw Patrol terminal demo"
    >
      <div ref={containerRef} class="asciinema-hero__player" />
      <noscript>
        <pre class="m-0 p-5 text-sm text-canvas overflow-x-auto">
          {`$ clawpatrol run codex
→ postgres query
  DROP TABLE sessions;
✗ denied by Claw Patrol
✓ audit log written`}
        </pre>
      </noscript>
    </div>
  );
}
