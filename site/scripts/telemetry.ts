// `npm run telemetry` — execute every .sql file in sql/telemetry/
// against the live D1 database in order, printing each result back
// to back. Reads stay read-only because each file is a SELECT; the
// runner doesn't validate that, so don't put DDL here.
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join, resolve } from "node:path";

const here = resolve(import.meta.dirname);
const dir = resolve(here, "..", "sql", "telemetry");
const files = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();

if (files.length === 0) {
  console.error(`no .sql files in ${dir}`);
  process.exit(1);
}

let failed = 0;
for (const f of files) {
  console.log(`\n== ${f} ==`);
  const r = spawnSync(
    "npx",
    [
      "wrangler", "d1", "execute", "TELEMETRY_DB",
      "--remote", "--file", join(dir, f),
    ],
    { stdio: "inherit" },
  );
  if (r.status !== 0) failed++;
}
process.exit(failed > 0 ? 1 : 0);
