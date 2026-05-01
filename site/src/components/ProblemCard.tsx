export function ProblemCard({
  headline,
  body,
}: {
  headline: string;
  body: string;
}) {
  return (
    <div class="p-8 rounded-sm bg-cream-dark border border-green-light">
      <p class="text-base font-semibold mb-3 text-console-dark font-display">
        {headline}
      </p>
      <p class="text-[15px] leading-relaxed text-text-muted font-sans">
        {body}
      </p>
    </div>
  );
}
