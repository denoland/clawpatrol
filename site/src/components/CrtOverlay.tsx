/** CRT screen effects — scanlines + refresh line.
 *  Overlay this inside a relative container with bg-crt-bg. */
export function CrtOverlay() {
  return (
    <>
      {/* Scanlines */}
      <div
        class="absolute inset-0 pointer-events-none z-30"
        style={{
          background:
            "repeating-linear-gradient(" +
            "0deg," +
            "rgba(255,255,255,0.03)," +
            "rgba(255,255,255,0.03) 1px," +
            "transparent 1px," +
            "transparent 3px" +
            ")",
        }}
      />
      {/* Refresh line */}
      <div
        class="absolute left-0 right-0 pointer-events-none z-30 h-0.5
          motion-reduce:hidden"
        style={{
          background:
            "linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.03) 20%, rgba(255,255,255,0.03) 80%, transparent 100%)",
          boxShadow: "0 0 10px 3px rgba(255,255,255,0.015)",
          animation: "crt-refresh 4s linear 1s infinite",
        }}
      />
      {/* Vignette — darkened edges */}
      <div
        class="absolute inset-0 pointer-events-none z-30"
        style={{
          boxShadow:
            "inset 0 0 80px rgba(0,0,0,0.4), inset 0 0 160px rgba(0,0,0,0.2)",
        }}
      />
    </>
  );
}
