export function Stripe() {
  const color1 = `var(--color-butter-300)`;
  const color2 = `var(--color-navy-500)`;
  const sizeInPx = 6;
  return (
    <div
      class="h-2.5 w-full"
      style={{
        background:
          "repeating-linear-gradient(" +
          "-60deg," +
          `${color1},` +
          `${color1} ${sizeInPx}px,` +
          `${color2} ${sizeInPx}px,` +
          `${color2} ${sizeInPx * 2}px` +
          ")",
      }}
    />
  );
}
