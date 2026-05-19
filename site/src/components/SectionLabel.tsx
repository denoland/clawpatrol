export function SectionLabel({ children }: { children: string }) {
  return (
    <h2 class="uppercase flex mx-auto text-sm w-max font-normal text-rust font-mono leading-none py-1.5 px-3 mb-8 bg-rust-100 border border-b-1.5 border-r-1.5 border-rust-200 squircle-md">
      {children}
    </h2>
  );
}
