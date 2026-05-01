type Props = {
  timeline?: string;
  range?: string;
};

export function ScrollHint({
  timeline = "--diagram",
  range = "cover 16% cover 24%",
}: Props) {
  return (
    <div
      class="scroll-hint absolute bottom-4 inset-x-0 z-20 flex-col items-center gap-1
        text-crt-dim/70 font-mono text-[0.625rem] uppercase tracking-[0.35em]
        pointer-events-none"
      style={{
        animationTimeline: timeline,
        animationRange: range,
      }}
    >
      <span>Scroll</span>
      <span class="motion-safe:animate-bounce text-sm tracking-normal">↓</span>
    </div>
  );
}
