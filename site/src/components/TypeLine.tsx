/** Renders each character as an individually-animated span.
 *  Characters appear one by one as the scroll timeline progresses
 *  through the range [startPct, endPct]. */
export function TypeLine({
  text,
  timeline,
  startPct,
  endPct,
  class: className,
}: {
  text: string;
  timeline: string;
  startPct: number;
  endPct: number;
  class?: string;
}) {
  const chars = text.split("");
  const range = endPct - startPct;

  return (
    <span class={className}>
      {chars.map((ch, i) => {
        const charStart = startPct + (i / chars.length) * range;
        const charEnd = startPct + ((i + 1) / chars.length) * range;
        return (
          <span
            key={i}
            class="dia-typed-char"
            style={{
              animationTimeline: timeline,
              animationRange: `cover ${charStart.toFixed(1)}% cover ${charEnd.toFixed(1)}%`,
            }}
          >
            {ch}
          </span>
        );
      })}
    </span>
  );
}

/** Same as TypeLine but for multiline text (preserves newlines). */
export function TypeBlock({
  text,
  timeline,
  startPct,
  endPct,
  class: className,
}: {
  text: string;
  timeline: string;
  startPct: number;
  endPct: number;
  class?: string;
}) {
  const lines = text.split("\n");
  // Count total non-newline characters for even distribution
  const totalChars = lines.reduce((sum, line) => sum + line.length, 0);
  const range = endPct - startPct;
  let charIndex = 0;

  return (
    <span class={className}>
      {lines.map((line, lineIdx) => (
        <span key={lineIdx}>
          {line.split("").map((ch, i) => {
            const globalIdx = charIndex++;
            const charStart = startPct + (globalIdx / totalChars) * range;
            const charEnd = startPct + ((globalIdx + 1) / totalChars) * range;
            return (
              <span
                key={i}
                class="dia-typed-char"
                style={{
                  animationTimeline: timeline,
                  animationRange: `cover ${charStart.toFixed(1)}% cover ${charEnd.toFixed(1)}%`,
                }}
              >
                {ch}
              </span>
            );
          })}
          {lineIdx < lines.length - 1 ? "\n" : ""}
        </span>
      ))}
    </span>
  );
}
