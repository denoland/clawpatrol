export function SectionLabel({ children }: { children: string }) {
  return (
    <div class="text-center mb-16">
      <h2
        class="text-lg uppercase flex items-center gap-4 mx-auto w-max
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
    class="h-4 w-13 "
    style={{
      background:
        "repeating-linear-gradient(" +
        "-60deg," +
        `var(--color-rust),` +
        `var(--color-rust) 4px,` +
        `transparent 4px,` +
        `transparent 8px` +
        ")",
    }}
  />
);
