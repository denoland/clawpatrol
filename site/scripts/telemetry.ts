// `npm run telemetry` — execute every .sql file in sql/telemetry/
// against the live D1 database in order, printing each result back
// to back as a small ASCII table. Reads stay read-only because each
// file is a SELECT; the runner doesn't validate that, so don't put
// DDL here.
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
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
  // wrangler --file returns import-style meta only; pass the SQL
  // through --command so the rows actually come back. Strip line
  // comments first — yargs treats a leading `-- ` token as the
  // end-of-options marker and splits the rest into positional args.
  const sql = readFileSync(join(dir, f), "utf8")
    .replace(/^\s*--.*$/gm, "")
    .replace(/\s+/g, " ")
    .trim();
  const r = spawnSync(
    "npx",
    [
      "wrangler", "d1", "execute", "TELEMETRY_DB",
      "--remote", "--json", "--command", sql,
    ],
    { encoding: "utf8" },
  );
  if (r.status !== 0) {
    process.stderr.write(r.stderr);
    failed++;
    continue;
  }
  // wrangler --json prints meta + diagnostics on stderr (which we
  // drop) and the actual payload on stdout.
  try {
    const out = JSON.parse(r.stdout);
    const rows = out?.[0]?.results ?? [];
    printRows(rows);
  } catch (e) {
    process.stdout.write(r.stdout);
  }
}
process.exit(failed > 0 ? 1 : 0);

function printRows(rows: Array<Record<string, unknown>>) {
  if (rows.length === 0) {
    console.log("(no rows)");
    return;
  }
  const cols = Object.keys(rows[0]);
  const widths = cols.map((c) =>
    Math.max(c.length, ...rows.map((r) => String(r[c] ?? "").length)),
  );
  const fmt = (vals: string[]) =>
    vals.map((v, i) => v.padEnd(widths[i])).join("  ");
  console.log(fmt(cols));
  console.log(fmt(widths.map((w) => "-".repeat(w))));
  for (const r of rows) {
    console.log(fmt(cols.map((c) => String(r[c] ?? ""))));
  }
}
