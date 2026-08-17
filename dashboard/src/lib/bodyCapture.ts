// These sentinels mirror the persisted body markers in cmd/clawpatrol/web.go.
export const BODY_TRUNCATED_MARKER = "\n[clawpatrol:body-truncated]";
export const BODY_INCOMPLETE_MARKER = "\n[clawpatrol:body-incomplete]";
export const BODY_ABORTED_MARKER = "\n[clawpatrol:body-aborted]";

export type BodyCaptureState = "complete" | "incomplete" | "aborted" | "unknown";

export type BodyCapture = {
  text: string;
  capped: boolean;
  state: BodyCaptureState;
};

// splitBodyCapture removes audit metadata before JSON/SSE parsing. New rows
// carry lifecycle state in dedicated columns; marker parsing remains only for
// rows written by versions that embedded lifecycle state in the body text.
export function splitBodyCapture(rawText: string, storedState?: string): BodyCapture {
  let text = rawText;
  let capped = false;
  let state: BodyCaptureState = normalizeBodyCaptureState(storedState);

  if (text.endsWith(BODY_TRUNCATED_MARKER)) {
    capped = true;
    text = text.slice(0, -BODY_TRUNCATED_MARKER.length);
  }
  if (!storedState) {
    if (text.endsWith(BODY_INCOMPLETE_MARKER)) {
      state = "incomplete";
      text = text.slice(0, -BODY_INCOMPLETE_MARKER.length);
    } else if (text.endsWith(BODY_ABORTED_MARKER)) {
      state = "aborted";
      text = text.slice(0, -BODY_ABORTED_MARKER.length);
    }
  }

  return { text, capped, state };
}

function normalizeBodyCaptureState(state?: string): BodyCaptureState {
  switch (state) {
    case "complete":
    case "incomplete":
    case "aborted":
      return state;
    default:
      return "unknown";
  }
}
