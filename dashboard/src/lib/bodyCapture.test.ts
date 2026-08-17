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
  assertEquals(splitBodyCapture(`{"ok":true}`), {
    text: `{"ok":true}`,
    capped: false,
    state: "complete",
  });
});

Deno.test("splitBodyCapture removes an incomplete marker before parsing", () => {
  assertEquals(splitBodyCapture(`{"partial":true}${BODY_INCOMPLETE_MARKER}`), {
    text: `{"partial":true}`,
    capped: false,
    state: "incomplete",
  });
});

Deno.test("splitBodyCapture removes an aborted marker before parsing", () => {
  assertEquals(splitBodyCapture(`partial${BODY_ABORTED_MARKER}`), {
    text: "partial",
    capped: false,
    state: "aborted",
  });
});

Deno.test("splitBodyCapture keeps lifecycle and cap truncation orthogonal", () => {
  assertEquals(splitBodyCapture(`partial${BODY_INCOMPLETE_MARKER}${BODY_TRUNCATED_MARKER}`), {
    text: "partial",
    capped: true,
    state: "incomplete",
  });
});
