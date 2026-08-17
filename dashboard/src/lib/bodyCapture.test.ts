import {
  BODY_ABORTED_MARKER,
  BODY_INCOMPLETE_MARKER,
  BODY_TRUNCATED_MARKER,
  splitBodyCapture,
} from "./bodyCapture.ts";

function assertEquals<T>(actual: T, expected: T): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`actual ${JSON.stringify(actual)} != expected ${JSON.stringify(expected)}`);
  }
}

Deno.test("splitBodyCapture leaves complete bodies unchanged", () => {
  assertEquals(splitBodyCapture(`{"ok":true}`, "complete"), {
    text: `{"ok":true}`,
    capped: false,
    state: "complete",
  });
});

Deno.test("splitBodyCapture uses structured incomplete state", () => {
  assertEquals(splitBodyCapture(`{"partial":true}`, "incomplete"), {
    text: `{"partial":true}`,
    capped: false,
    state: "incomplete",
  });
});

Deno.test("splitBodyCapture uses structured aborted state", () => {
  assertEquals(splitBodyCapture("partial", "aborted"), {
    text: "partial",
    capped: false,
    state: "aborted",
  });
});

Deno.test("splitBodyCapture keeps structured state and cap truncation orthogonal", () => {
  assertEquals(splitBodyCapture(`partial${BODY_TRUNCATED_MARKER}`, "incomplete"), {
    text: "partial",
    capped: true,
    state: "incomplete",
  });
});

Deno.test("splitBodyCapture marks legacy rows with no state as unknown", () => {
  assertEquals(splitBodyCapture("legacy body"), {
    text: "legacy body",
    capped: false,
    state: "unknown",
  });
});

Deno.test("splitBodyCapture understands legacy lifecycle markers", () => {
  assertEquals(splitBodyCapture(`partial${BODY_ABORTED_MARKER}${BODY_TRUNCATED_MARKER}`), {
    text: "partial",
    capped: true,
    state: "aborted",
  });
});

Deno.test("structured state prevents lifecycle-marker suffix ambiguity", () => {
  const text = `literal${BODY_INCOMPLETE_MARKER}`;
  assertEquals(splitBodyCapture(text, "complete"), {
    text,
    capped: false,
    state: "complete",
  });
});
