import type { ComponentChildren } from "preact";

export function CrtDisplay({
  title,
  children,
}: {
  title?: string;
  children: ComponentChildren;
}) {
  return (
    <div
      class="md:squircle-xl bg-canvas py-[clamp(20px,3.5vw,34px)] md:p-[clamp(20px,3.5vw,34px)]"
      style={{
        boxShadow:
          "2px 3px 14px rgba(42,52,47,0.08), " +
          "5px 6px 32px rgba(42,52,47,0.08), " +
          "14px 16px 60px rgba(42,52,47,0.065), " +
          "24px 28px 90px rgba(42,52,47,0.05), " +
          "38px 42px 120px rgba(42,52,47,0.04), " +
          "52px 56px 160px rgba(42,52,47,0.025), " +
          "68px 72px 200px rgba(42,52,47,0.018), " +
          "-4px -4px 12px rgba(240,235,227,0.5), " +
          "-10px -10px 30px rgba(240,235,227,0.3), " +
          "inset 6px 6px 10px rgba(240,235,227,1), " +
          "inset -10px -10px 16px rgba(0,0,0,0.12)",
      }}
    >
      <div
        class="md:squircle-lg overflow-hidden relative bg-crt-bg"
        style={{
          boxShadow:
            "inset 0 0 18px rgba(0,0,0,0.9), " +
            "inset 0 0 40px rgba(0,0,0,0.5), " +
            "inset -5px -5px 10px rgba(42,52,47,1), " +
            "3px 3px 4px rgba(240,235,227,0.7), " +
            "6px 6px 10px rgba(240,235,227,0.7), " +
            "-3px -3px 4px rgba(42,52,47,0.3), " +
            "-6px -6px 10px rgba(42,52,47,0.18), " +
            "0 0 3px rgba(240,235,227,1), " +
            "0 0 3px rgba(42,52,47,0.15)",
        }}
      >
        {/* Glass reflection */}
        <div
          class="absolute pointer-events-none z-20 w-60 h-12
            rounded-full bg-white blur-xl top-4 left-2 opacity-20"
        />
        <div
          class="absolute pointer-events-none z-20 w-8 h-18
            rounded-full bg-white blur-lg bottom-4 right-4 opacity-15"
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
