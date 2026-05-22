import type { ComponentChildren } from "preact";

export function CrtDisplay({
  title,
  children,
}: {
  title?: string;
  children: ComponentChildren;
}) {
  return (
    <div>
      <div class="lg:squircle-lg overflow-hidden relative bg-navy-700">
        {/* Glass reflection */}
        <div
          class="absolute pointer-events-none z-20 w-60 h-12
            rounded-full bg-canvas-light blur-xl top-4 left-2 opacity-20"
        />
        <div
          class="absolute pointer-events-none z-20 w-8 h-18
            rounded-full bg-canvas-light blur-lg bottom-4 right-4 opacity-15"
        />
        {/* CRT refresh line */}
        <div
          class="absolute left-0 right-0 pointer-events-none z-20 h-0.5
            motion-reduce:hidden"
          style={{
            background:
              "linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.05) 20%, rgba(255,255,255,0.05) 80%, transparent 100%)",
            boxShadow: "0 0 10px 3px rgba(255,255,255,0.02)",
            animation: "crt-refresh 4s linear 1s infinite",
          }}
        />
        {/* CRT scanlines */}
        <div
          class="absolute inset-0 pointer-events-none z-10"
          style={{
            background:
              "repeating-linear-gradient(" +
              "0deg," +
              "rgba(255,255,255,0.045)," +
              "rgba(255,255,255,0.045) 1px," +
              "transparent 1px," +
              "transparent 3px" +
              ")",
          }}
        />
        {title && (
          <div
            class="px-6 sm:px-8 py-3 sm:py-4 text-xs flex items-center
              gap-2 font-mono text-crt-dim border-b border-crt-border"
          >
            <span
              class="inline-block w-2 h-2 rounded-full bg-crt"
              style={{ boxShadow: "0 0 6px var(--color-crt)" }}
            />
            {title}
          </div>
        )}
        {children}
      </div>
    </div>
  );
}
