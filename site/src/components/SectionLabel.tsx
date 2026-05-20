export function SectionLabel({ children }: { children: string }) {
  return (
    <h2 class="uppercase flex mx-auto text-sm w-max font-normal text-rust-50 font-mono leading-none py-1.5 px-3 mb-8 bg-rust squircle-lg">
      {children}
    </h2>
  );
}
