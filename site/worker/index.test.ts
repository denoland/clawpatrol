import assert from "node:assert/strict";
import { test } from "node:test";

import worker, { isUpdateAvailable } from "./index";

type PreparedStatement = {
  bind: (...args: unknown[]) => PreparedStatement;
  run: () => Promise<void>;
};

function env() {
  const calls = { prepare: 0, bind: [] as unknown[][], releaseFetch: 0 };
  const stmt: PreparedStatement = {
    bind: (...args: unknown[]) => {
      calls.bind.push(args);
      return stmt;
    },
    run: async () => {},
  };
  const testEnv = {
    ASSETS: { fetch: async (_req: Request) => new Response("asset") } as Fetcher,
    TELEMETRY_DB: {
      prepare: () => {
        calls.prepare++;
        return stmt;
      },
    } as unknown as D1Database,
  };
  return { calls, env: testEnv };
}

const originalFetch = globalThis.fetch;

test.afterEach(() => {
  globalThis.fetch = originalFetch;
});

test("rejects oversized telemetry payloads from Content-Length before reading the body", async () => {
  const { env: testEnv, calls } = env();
  const body = new ReadableStream({
    pull(controller) {
      controller.error(new Error("body should not be read"));
    },
  });
  const req = new Request("https://clawpatrol.dev/api/telemetry/v1/check", {
    method: "POST",
    headers: { "Content-Length": "4097" },
    body,
    duplex: "half",
  } as RequestInit & { duplex: "half" });

  const res = await worker.fetch(req, testEnv);

  assert.equal(res.status, 413);
  assert.equal(calls.prepare, 0);
});

test("rejects payloads over the byte limit, not just the JavaScript string length", async () => {
  const { env: testEnv, calls } = env();
  globalThis.fetch = async () => {
    calls.releaseFetch++;
    return Response.json({ tag_name: "v1.0.0", html_url: "https://example.com" });
  };
  const text = JSON.stringify({
    instance_id: "01HZTEST",
    version: "0.4.2",
    os: "linux",
    arch: "amd64",
    git_sha: "€".repeat(1400),
  });
  assert.ok(text.length <= 4096);
  assert.ok(new TextEncoder().encode(text).byteLength > 4096);

  const res = await worker.fetch(
    new Request("https://clawpatrol.dev/api/telemetry/v1/check", {
      method: "POST",
      body: text,
    }),
    testEnv,
  );

  assert.equal(res.status, 413);
  assert.equal(calls.prepare, 0);
  assert.equal(calls.releaseFetch, 0);
});

test("rejects oversized telemetry without Content-Length before reading all chunks", async () => {
  const { env: testEnv, calls } = env();
  let pulls = 0;
  const chunk = new Uint8Array(2048);
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls++;
      controller.enqueue(chunk);
      if (pulls >= 4) controller.close();
    },
  });

  const res = await worker.fetch(
    new Request("https://clawpatrol.dev/api/telemetry/v1/check", {
      method: "POST",
      body,
      duplex: "half",
    } as RequestInit & { duplex: "half" }),
    testEnv,
  );

  assert.equal(res.status, 413);
  assert.equal(calls.prepare, 0);
  assert.ok(pulls < 4, `expected early cancellation, read ${pulls} chunks`);
});

test("compares update versions by major/minor/patch and ignores build metadata", () => {
  const cases = [
    { current: "1.2.3", latest: "v1.2.4", want: true },
    { current: "1.2.3", latest: "v1.3.0", want: true },
    { current: "1.2.3", latest: "v2.0.0", want: true },
    { current: "1.2.3-rc.1", latest: "v1.2.3", want: true },
    { current: "1.2.3-beta.1", latest: "v1.2.3-rc.1", want: true },
    { current: "1.2.3-rc.2", latest: "v1.2.3-rc.10", want: true },
    { current: "1.2.3-alpha.10", latest: "v1.2.3-alpha.2", want: false },
    { current: "1.2.3", latest: "v1.2.3", want: false },
    { current: "1.2.3+local", latest: "v1.2.3+build.5", want: false },
    { current: "1.2.3", latest: "v1.2.3-rc.1", want: false },
    { current: "1.2.4", latest: "v1.2.3", want: false },
    { current: "", latest: "v1.2.4", want: false },
    { current: "dev", latest: "v1.2.4", want: false },
    { current: "1.2", latest: "v1.2.4", want: false },
    { current: "1.2.3", latest: "", want: false },
  ];

  for (const tc of cases) {
    assert.equal(
      isUpdateAvailable(tc.current, tc.latest),
      tc.want,
      `${tc.current} vs ${tc.latest}`,
    );
  }
});
