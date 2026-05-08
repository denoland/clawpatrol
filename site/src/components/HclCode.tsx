/* Tiny HCL tokenizer. Just enough to colorize the `rule { ... }`
   snippets on the landing page — not a real parser. Palette matches
   the hand-tinted block in RulesSection. */

type Tok = {
  kind: "kw" | "str" | "cmt" | "key" | "txt";
  text: string;
};

const KEYWORDS = new Set([
  "rule",
  "endpoint",
  "endpoints",
  "credential",
  "credentials",
  "approver",
  "policy",
  "profile",
  "match",
  "verdict",
  "approve",
  "reason",
  "priority",
  "disabled",
  "defaults",
]);

function tokenize(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === "#") {
      const end = src.indexOf("\n", i);
      const stop = end < 0 ? src.length : end;
      out.push({ kind: "cmt", text: src.slice(i, stop) });
      i = stop;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== '"') {
        if (src[j] === "\\") j++;
        j++;
      }
      out.push({ kind: "str", text: src.slice(i, j + 1) });
      i = j + 1;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i + 1;
      while (j < src.length && /[A-Za-z0-9_-]/.test(src[j])) j++;
      const word = src.slice(i, j);
      let k = j;
      while (k < src.length && (src[k] === " " || src[k] === "\t")) k++;
      const isKey = src[k] === "=";
      out.push({
        kind: KEYWORDS.has(word) ? "kw" : isKey ? "key" : "txt",
        text: word,
      });
      i = j;
      continue;
    }
    let j = i;
    while (j < src.length && !/[A-Za-z_#"]/.test(src[j])) j++;
    out.push({ kind: "txt", text: src.slice(i, j) });
    i = j;
  }
  return out;
}

const CLASS: Record<Tok["kind"], string> = {
  kw: "text-rust-300",
  str: "text-butter-300",
  cmt: "text-canvas/40",
  key: "text-canvas/70",
  txt: "",
};

export function HclCode(
  { source, class: cls }: { source: string; class?: string },
) {
  const toks = tokenize(source);
  return (
    <pre class={cls ?? ""}>
      <code>
        {toks.map((t, i) => (
          <span key={i} class={CLASS[t.kind]}>{t.text}</span>
        ))}
      </code>
    </pre>
  );
}
