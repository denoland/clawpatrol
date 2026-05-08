type StripeArgs = {
  color1?: string;
  color2?: string;
};

export function Stripe({ color1, color2 }: StripeArgs) {
  const stripeA = color1 ?? `var(--color-rust)`;
  const stripeB = color2 ?? `transparent`;
  const sizeInPx = 5;
  return (
    <div
      class="h-3 w-full"
      style={{
        background:
          "repeating-linear-gradient(" +
          "-60deg," +
          `${stripeA},` +
          `${stripeA} ${sizeInPx}px,` +
          `${stripeB} ${sizeInPx}px,` +
          `${stripeB} ${sizeInPx * 2}px` +
          ")",
      }}
    />
  );
}
