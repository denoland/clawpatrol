import assert from "node:assert/strict";
import { test } from "node:test";

import worker from "./index";

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
  return {
    calls,
    env: {
      ASSETS: { fetch: async () => new Response("asset") },
      TELEMETRY_DB: {
        prepare: () => {
          calls.prepare++;
          return stmt;
        },
      },
    },
  };
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

test("check ping with version=dev is dropped without touching the DB", async () => {
  const { env: testEnv, calls } = env();
  globalThis.fetch = async () => {
    calls.releaseFetch++;
    return Response.json({ tag_name: "v1.0.0", html_url: "https://x" });
  };
  const res = await worker.fetch(
    new Request("https://clawpatrol.dev/api/telemetry/v1/check", {
      method: "POST",
      body: JSON.stringify({
        instance_id: "01HZDEV",
        version: "dev",
        os: "linux",
        arch: "amd64",
      }),
    }),
    testEnv,
  );

  assert.equal(res.status, 204);
  assert.equal(calls.prepare, 0);
  assert.equal(calls.releaseFetch, 0);
});

test("install ping inserts a row and 204s", async () => {
  const { env: testEnv, calls } = env();
  const body = JSON.stringify({
    install_id: "abcd1234",
    event: "completed",
    os: "darwin",
    arch: "arm64",
    version: "latest",
    from_source: "0",
    reason: "",
  });
  const res = await worker.fetch(
    new Request("https://clawpatrol.dev/api/telemetry/v1/install", {
      method: "POST",
      body,
    }),
    testEnv,
  );

  assert.equal(res.status, 204);
  assert.equal(calls.prepare, 1);
  const bound = calls.bind[0];
  assert.equal(bound[0], "abcd1234");
  assert.equal(bound[2], "completed");
  assert.equal(bound[3], "darwin");
  assert.equal(bound[4], "arm64");
  assert.equal(bound[6], 0);
});

test("install ping rejects unknown event names", async () => {
  const { env: testEnv, calls } = env();
  const res = await worker.fetch(
    new Request("https://clawpatrol.dev/api/telemetry/v1/install", {
      method: "POST",
      body: JSON.stringify({ install_id: "x", event: "bogus" }),
    }),
    testEnv,
  );

  assert.equal(res.status, 400);
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
