import { hydrate, render } from "preact";
import { Landing } from "./Landing";
import "./index.css";

// In production the build step prerenders <Landing /> into #root, so
// we hydrate against existing markup. In dev vite serves an empty
// root div — hydrate would no-op there, so fall back to render.
const root = document.getElementById("root")!;
if (root.firstChild) {
  hydrate(<Landing />, root);
} else {
  render(<Landing />, root);
}

// Load interactive chart after the tree is mounted.
import("./chart");
