export function SectionLabel({ children }: { children: string }) {
  return (
    <div class="text-center mb-16">
      <h2
        class="inline-block text-[11px] uppercase
          tracking-[0.35em] px-6 py-2.5 font-black
          bg-persimmon text-text font-display
          shadow-[2px_2px_0_var(--color-console-dark)]"
      >
        {children}
      </h2>
    </div>
  );
}
