/// <reference lib="deno.ns" />
import { headersToJSON } from "./clipboard";

Deno.test("headersToJSON: single-value headers serialise as strings", () => {
  const out = headersToJSON({
    "content-type": "application/json",
    "x-request-id": "abc123",
  });
  const parsed = JSON.parse(out);
  if (parsed["content-type"] !== "application/json") {
    throw new Error(
      `expected content-type as string, got ${JSON.stringify(parsed["content-type"])}`,
    );
  }
  if (parsed["x-request-id"] !== "abc123") {
    throw new Error(
      `expected x-request-id as string, got ${JSON.stringify(parsed["x-request-id"])}`,
    );
  }
});

Deno.test("headersToJSON: multi-value headers serialise as arrays", () => {
  const out = headersToJSON({
    "set-cookie": ["a=1; Path=/", "b=2; Secure"],
  });
  const parsed = JSON.parse(out);
  if (!Array.isArray(parsed["set-cookie"])) {
    throw new Error(`expected set-cookie as array, got ${typeof parsed["set-cookie"]}`);
  }
  if (parsed["set-cookie"].length !== 2) {
    throw new Error(`expected 2 cookies, got ${parsed["set-cookie"].length}`);
  }
  if (parsed["set-cookie"][0] !== "a=1; Path=/" || parsed["set-cookie"][1] !== "b=2; Secure") {
    throw new Error(`unexpected values: ${JSON.stringify(parsed["set-cookie"])}`);
  }
});

Deno.test("headersToJSON: empty header map produces empty object", () => {
  const out = headersToJSON({});
  if (out !== "{}") {
    throw new Error(`expected '{}', got ${JSON.stringify(out)}`);
  }
});

Deno.test("headersToJSON: empty header value preserved", () => {
  const out = headersToJSON({ "x-empty": "" });
  const parsed = JSON.parse(out);
  if (parsed["x-empty"] !== "") {
    throw new Error(`expected empty string, got ${JSON.stringify(parsed["x-empty"])}`);
  }
});

Deno.test("headersToJSON: single-element array collapses to string", () => {
  const out = headersToJSON({ "x-once": ["only"] });
  const parsed = JSON.parse(out);
  if (parsed["x-once"] !== "only") {
    throw new Error(
      `expected single-element array to collapse to string, got ${JSON.stringify(parsed["x-once"])}`,
    );
  }
});

Deno.test("headersToJSON: special characters are JSON-escaped", () => {
  const out = headersToJSON({
    "x-quote": 'he said "hi"',
    "x-backslash": "a\\b",
    "x-newline": "line1\nline2",
    "x-tab": "a\tb",
    "x-unicode": "café 漢字 🚀",
  });
  const parsed = JSON.parse(out);
  if (parsed["x-quote"] !== 'he said "hi"') throw new Error("quote round-trip failed");
  if (parsed["x-backslash"] !== "a\\b") throw new Error("backslash round-trip failed");
  if (parsed["x-newline"] !== "line1\nline2") throw new Error("newline round-trip failed");
  if (parsed["x-tab"] !== "a\tb") throw new Error("tab round-trip failed");
  if (parsed["x-unicode"] !== "café 漢字 🚀") throw new Error("unicode round-trip failed");
});

Deno.test("headersToJSON: output is pretty-printed with 2-space indent", () => {
  const out = headersToJSON({ a: "1", b: "2" });
  if (!out.includes("\n")) {
    throw new Error("expected newlines in pretty-printed output");
  }
  if (!out.includes('  "a"')) {
    throw new Error(`expected 2-space indent, got: ${out}`);
  }
});
