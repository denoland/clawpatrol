type StripeArgs = {
  color1?: string;
  color2?: string;
};

export function Stripe({ color1, color2 }: StripeArgs) {
  const stripeA = color1 ?? `var(--color-rust)`;
  const stripeB = color2 ?? `transparent`;
  // Each stripeA band is `stripeWidth` wide; the band repeats every
  // `pitch` so the gap between stripes is (pitch - stripeWidth).
  // Stripe-to-gap ratio of ~1:2 reads thin/editorial, not stacked.
  const stripeWidth = 2;
  const pitch = 4;
  return (
    <div
      class="h-3 w-full"
      style={{
        background:
          "repeating-linear-gradient(" +
          "-60deg," +
          `${stripeA},` +
          `${stripeA} ${stripeWidth}px,` +
          `${stripeB} ${stripeWidth}px,` +
          `${stripeB} ${pitch}px` +
          ")",
      }}
    />
  );
}
