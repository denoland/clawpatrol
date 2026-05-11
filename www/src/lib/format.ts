export function fmtBytes(n: number): string {
  if (!n) return "0";
  const u = ["B", "K", "M", "G"];
  let i = 0,
    x = n;
  while (x >= 1024 && i < u.length - 1) {
    x /= 1024;
    i++;
  }
  return x.toFixed(x < 10 && i > 0 ? 1 : 0) + u[i];
}

export function fmtAge(t: string | undefined): string {
  if (!t) return "—";
  const sec = Math.floor((Date.now() - new Date(t).getTime()) / 1000);
  if (sec < 60) return sec + "s";
  if (sec < 3600) return Math.floor(sec / 60) + "m";
  if (sec < 86400) return Math.floor(sec / 3600) + "h";
  return Math.floor(sec / 86400) + "d";
}

export function fmtTokens(n?: number): string {
  if (!n) return "0";
  if (n < 1000) return String(n);
  if (n < 1_000_000) return (n / 1000).toFixed(n < 10_000 ? 1 : 0) + "k";
  return (n / 1_000_000).toFixed(1) + "M";
}

export function shortModel(m?: string): string {
  if (!m) return "";
  // claude-sonnet-4-5-20251022 → sonnet 4-5
  let s = m.toLowerCase();
  s = s.replace(/^claude-/, "");
  s = s.replace(/-\d{8}$/, "");
  s = s.replace(/-(20\d{6})$/, "");
  s = s.replace(/^gpt-/, "gpt ");
  s = s.replace(/^anthropic\./, "");
  return s;
}

export function fmtExpiry(unix?: number): string {
  if (!unix) return "—";
  const sec = unix - Math.floor(Date.now() / 1000);
  if (sec < 0) return "expired";
  if (sec < 3600) return "in " + Math.floor(sec / 60) + "m";
  if (sec < 86400) return "in " + Math.floor(sec / 3600) + "h";
  return "in " + Math.floor(sec / 86400) + "d";
}
