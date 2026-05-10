import Prism from "prismjs";
import "prismjs/components/prism-diff";
import "prismjs/plugins/diff-highlight/prism-diff-highlight";
import "prismjs/plugins/diff-highlight/prism-diff-highlight.css";

// Prism.highlight returns escaped token HTML. ConfigSaveReview injects this
// string into a read-only <code> element so Prism can style diff tokens.
export function highlightDiff(diff: string): string {
  return Prism.highlight(diff, Prism.languages.diff, "diff");
}
