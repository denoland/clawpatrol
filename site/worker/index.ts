/// <reference types="@cloudflare/workers-types" />
// Cloudflare Worker for clawpatrol.dev. Two responsibilities:
//
//   1. Serve the static landing site (env.ASSETS, built into ./dist
//      by `npm run build`).
//   2. Accept telemetry pings from clawpatrol gateways at
//      POST /api/telemetry/v1/check, upsert into D1, and return the
//      latest GitHub release as the update-checker response.
//
// Contract for what's stored: doc/telemetry.md.

interface Env {
  ASSETS: Fetcher;
  TELEMETRY_DB: D1Database;
}

const MAX_BODY_BYTES = 4096;
const RELEASES_URL =
  "https://api.github.com/repos/denoland/clawpatrol/releases/latest";

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/api/telemetry/v1/check") {
      return handleCheck(req, env);
    }
    return env.ASSETS.fetch(req);
  },
};

async function handleCheck(
  req: Request,
  env: Env,
): Promise<Response> {
  if (req.method !== "POST") {
    return new Response(null, { status: 405 });
  }
  const contentLength = req.headers.get("Content-Length");
  if (contentLength !== null) {
    const n = Number(contentLength);
    if (Number.isFinite(n) && n > MAX_BODY_BYTES) {
      return new Response(null, { status: 413 });
    }
  }

  const bodyText = await readRequestBody(req, MAX_BODY_BYTES);
  if (bodyText === null) {
    return new Response(null, { status: 413 });
  }

  let body: Record<string, unknown>;
  try {
    body = JSON.parse(bodyText);
  } catch {
    return new Response(null, { status: 400 });
  }

  const id = str(body.instance_id);
  const version = str(body.version);
  const os = str(body.os);
  const arch = str(body.arch);
  if (!id || !version || !os || !arch) {
    return new Response(null, { status: 400 });
  }

  const now = Math.floor(Date.now() / 1000);
  await env.TELEMETRY_DB.prepare(
    `INSERT INTO gateways (
       instance_id, first_seen, last_seen,
       version, git_sha, os, arch, go_version, transport,
       uptime_s, connected_devices_1h, actions_count_1h,
       bytes_in_1h, bytes_out_1h, payload
     ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
     ON CONFLICT(instance_id) DO UPDATE SET
       last_seen            = excluded.last_seen,
       version              = excluded.version,
       git_sha              = excluded.git_sha,
       os                   = excluded.os,
       arch                 = excluded.arch,
       go_version           = excluded.go_version,
       transport            = excluded.transport,
       uptime_s             = excluded.uptime_s,
       connected_devices_1h = excluded.connected_devices_1h,
       actions_count_1h     = excluded.actions_count_1h,
       bytes_in_1h          = excluded.bytes_in_1h,
       bytes_out_1h         = excluded.bytes_out_1h,
       payload              = excluded.payload`,
  ).bind(
    id, now, now,
    version, str(body.git_sha), os, arch,
    str(body.go_version), str(body.transport),
    intOrNull(body.uptime_s),
    intOrNull(body.connected_devices_1h),
    intOrNull(body.actions_count_1h),
    intOrNull(body.bytes_in_1h),
    intOrNull(body.bytes_out_1h),
    bodyText,
  ).run();

  const release = await fetchLatestRelease();
  const updateAvailable = isUpdateAvailable(version, release.tag);
  return Response.json({
    latest: release.tag,
    your_version: version,
    update_available: updateAvailable,
    url: release.url,
    advisory: release.advisory,
  });
}

type Release = {
  tag: string;
  url: string;
  advisory: { level: string; message: string } | null;
};

async function readRequestBody(
  req: Request,
  limitBytes: number,
): Promise<string | null> {
  if (!req.body) return "";
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;

      const remaining = limitBytes + 1 - total;
      if (value.byteLength > remaining) {
        chunks.push(value.slice(0, remaining));
        await reader.cancel();
        return null;
      }

      total += value.byteLength;
      chunks.push(value);
      if (total > limitBytes) {
        await reader.cancel();
        return null;
      }
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

async function fetchLatestRelease(): Promise<Release> {
  const r = await fetch(RELEASES_URL, {
    headers: {
      "User-Agent": "clawpatrol-telemetry-worker",
      Accept: "application/vnd.github+json",
    },
    cf: { cacheTtl: 1800, cacheEverything: true },
  });
  if (!r.ok) return { tag: "", url: "", advisory: null };
  const data = await r.json() as {
    tag_name?: string;
    html_url?: string;
    body?: string;
  };
  const tag = (data.tag_name ?? "").replace(/^v/, "");
  const url = data.html_url ?? "";
  return { tag, url, advisory: parseAdvisory(data.body ?? "") };
}

function parseAdvisory(
  body: string,
): { level: string; message: string } | null {
  const m = body.match(/^\[(security|advisory)\]\s*([\s\S]*)/i);
  if (!m) return null;
  const firstPara = m[2].split(/\n\s*\n/)[0].trim();
  if (!firstPara) return null;
  return { level: m[1].toLowerCase(), message: firstPara };
}


export function isUpdateAvailable(current: string, latest: string): boolean {
  const currentVersion = parseVersion(current);
  const latestVersion = parseVersion(latest);
  if (!currentVersion || !latestVersion) return false;
  for (const key of ["major", "minor", "patch"] as const) {
    if (latestVersion[key] > currentVersion[key]) return true;
    if (latestVersion[key] < currentVersion[key]) return false;
  }
  if (currentVersion.prerelease && !latestVersion.prerelease) return true;
  if (!currentVersion.prerelease && latestVersion.prerelease) return false;
  if (currentVersion.prerelease && latestVersion.prerelease) {
    return comparePrerelease(latestVersion.prerelease, currentVersion.prerelease) > 0;
  }
  return false;
}

function comparePrerelease(a: string, b: string): number {
  const aa = a.split(".");
  const bb = b.split(".");
  const n = Math.max(aa.length, bb.length);
  for (let i = 0; i < n; i++) {
    const av = aa[i];
    const bv = bb[i];
    if (av === undefined) return -1;
    if (bv === undefined) return 1;
    if (av === bv) continue;
    const an = /^[0-9]+$/.test(av) ? Number(av) : null;
    const bn = /^[0-9]+$/.test(bv) ? Number(bv) : null;
    if (an !== null && bn !== null) return an > bn ? 1 : -1;
    if (an !== null) return -1;
    if (bn !== null) return 1;
    return av > bv ? 1 : -1;
  }
  return 0;
}

function parseVersion(
  version: string,
): { major: number; minor: number; patch: number; prerelease: string | null } | null {
  const m = version
    .trim()
    .match(/^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!m) return null;
  const major = Number(m[1]);
  const minor = Number(m[2]);
  const patch = Number(m[3]);
  if (![major, minor, patch].every(Number.isSafeInteger)) return null;
  return { major, minor, patch, prerelease: m[4] ?? null };
}

function str(v: unknown): string {
  if (typeof v !== "string") return "";
  if (v.length === 0 || v.length > 200) return "";
  return v;
}

function intOrNull(v: unknown): number | null {
  if (typeof v !== "number" || !Number.isFinite(v)) return null;
  if (v < 0) return null;
  return Math.floor(v);
}
