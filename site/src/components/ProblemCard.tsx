export function ProblemCard({ headline, body }: { headline: string; body: string }) {
  return (
    <div class="p-8 rounded-sm bg-canvas-dark border border-navy-200">
      <p class="text-base font-semibold mb-3 text-console-dark font-display">{headline}</p>
      <p class="text-[15px]  text-text-muted font-sans">{body}</p>
    </div>
  );
}
