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

function pad(n: number, width = 2): string {
  return String(n).padStart(width, "0");
}

// fmtDateTime renders local time as `yyyy-MM-dd HH:mm:ss.SSS`. Used
// everywhere a timestamp shows up in the UI — keeps the format
// locale-independent. See AGENTS.md.
export function fmtDateTime(t: string | number | Date): string {
  const d = t instanceof Date ? t : new Date(t);
  return (
    d.getFullYear() +
    "-" +
    pad(d.getMonth() + 1) +
    "-" +
    pad(d.getDate()) +
    " " +
    pad(d.getHours()) +
    ":" +
    pad(d.getMinutes()) +
    ":" +
    pad(d.getSeconds()) +
    "." +
    pad(d.getMilliseconds(), 3)
  );
}

// fmtTime renders local time as `HH:mm:ss.SSS` (date omitted).
export function fmtTime(t: string | number | Date): string {
  const d = t instanceof Date ? t : new Date(t);
  return (
    pad(d.getHours()) +
    ":" +
    pad(d.getMinutes()) +
    ":" +
    pad(d.getSeconds()) +
    "." +
    pad(d.getMilliseconds(), 3)
  );
}

export function fmtExpiry(unix?: number): string {
  if (!unix) return "—";
  const sec = unix - Math.floor(Date.now() / 1000);
  if (sec < 0) return "expired";
  if (sec < 3600) return "in " + Math.floor(sec / 60) + "m";
  if (sec < 86400) return "in " + Math.floor(sec / 3600) + "h";
  return "in " + Math.floor(sec / 86400) + "d";
}

// statusClass buckets an action status string for coloring + analytics: a
// numeric HTTP-style status by its leading digit, a non-empty non-numeric
// status (e.g. a plugin's "AccessDenied") as "error" — a named status is a
// failure; success reports a 2xx — and an empty status as "".
export function statusClass(
  status: string | undefined,
): "" | "2xx" | "3xx" | "4xx" | "5xx" | "error" {
  if (!status) return "";
  const n = Number(status);
  if (Number.isNaN(n)) return "error";
  if (n >= 500) return "5xx";
  if (n >= 400) return "4xx";
  if (n >= 300) return "3xx";
  if (n >= 200) return "2xx";
  return "";
}

// statusColorClass maps a status string to a Tailwind text color.
export function statusColorClass(status: string | undefined): string {
  switch (statusClass(status)) {
    case "5xx":
      return "text-danger-500";
    case "error":
    case "4xx":
      return "text-rust-500";
    case "3xx":
      return "text-butter-600";
    case "2xx":
      return "text-success-600";
    default:
      return "text-text-muted";
  }
}
