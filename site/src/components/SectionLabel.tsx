export function SectionLabel({ children }: { children: string }) {
  return (
    <div class="text-center mb-16">
      <h2
        class="text-xl uppercase flex items-center gap-2 mx-auto w-max
          font-bold
           text-rust font-sans"
      >
        <Stripes />
        {children}
        <Stripes />
      </h2>
    </div>
  );
}

const Stripes = () => (
  <div
    class="h-4 w-12"
    style={{
      background:
        "repeating-linear-gradient(" +
        "90deg," +
        `transparent,` +
        `transparent 2px,` +
        `var(--color-rust) 2px,` +
        `var(--color-rust) 6px,` +
        `transparent 6px,` +
        `transparent 8px` +
        ")",
      transform: `skewX(-20deg)`,
    }}
  />
);
