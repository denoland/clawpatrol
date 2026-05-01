import { render } from "preact";
import { Landing } from "./Landing";
import "./index.css";

render(<Landing />, document.getElementById("root")!);

// Load interactive chart after render.
import("./chart");
