// User avatar: tries github.com/{user}.png if user looks like a github
// handle/email; falls back to initial-on-gray-circle.

import { useState } from "react";

const PALETTE = ["#a78bfa", "#f87171", "#fbbf24", "#34d399", "#60a5fa", "#f472b6", "#facc15"];

function colorFor(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return PALETTE[h % PALETTE.length];
}

function initial(s: string): string {
  const m = s.match(/[a-zA-Z0-9]/);
  return (m ? m[0] : "?").toUpperCase();
}

function ghHandle(user: string): string | null {
  // strip @domain → use local part as github guess
  const at = user.indexOf("@");
  if (at <= 0) return null;
  const handle = user.slice(0, at);
  if (!/^[a-zA-Z0-9-]+$/.test(handle)) return null;
  return handle;
}

export function Avatar({ user, size = 18 }: { user: string; size?: number }) {
  const [failed, setFailed] = useState(false);
  const handle = ghHandle(user || "");
  const src = handle ? `https://github.com/${handle}.png?size=${size * 2}` : null;
  if (src && !failed) {
    return (
      <img
        src={src}
        alt={user}
        onError={() => setFailed(true)}
        className="rounded-full block"
        style={{ width: size, height: size }}
      />
    );
  }
  const c = colorFor(user || "?");
  return (
    <span
      className="rounded-full inline-flex items-center justify-center text-white font-semibold"
      style={{ width: size, height: size, background: c, fontSize: Math.round(size * 0.5) }}
    >
      {initial(user || "?")}
    </span>
  );
}
