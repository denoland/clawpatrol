// Facet schema cache for the dashboard. The gateway exposes
// GET /api/facets — every registered protocol-family plugin's
// match-key and report-field schema. The dashboard fetches it once
// at boot and uses it to render per-family columns (HTTPS:
// method/path/status, SQL: verb/tables/..., k8s: verb/resource/...)
// without hardcoding the list of families in the frontend.
import { useEffect, useState } from "react";

import { type FacetSchema, getFacets } from "./api";

// Module-level cache so every component that asks for facets
// triggers exactly one fetch even when many mount on the same page
// (live feed + analytics + detail page can all render side by side).
let cache: FacetSchema[] | undefined;
let inflight: Promise<FacetSchema[]> | undefined;
const listeners = new Set<(facets: FacetSchema[]) => void>();

async function load(): Promise<FacetSchema[]> {
  if (cache) return cache;
  if (!inflight) {
    inflight = getFacets().then(
      (facets) => {
        cache = facets;
        inflight = undefined;
        for (const fn of listeners) fn(facets);
        return facets;
      },
      (err) => {
        inflight = undefined;
        throw err;
      },
    );
  }
  return inflight;
}

export function useFacets(): {
  byFamily: Record<string, FacetSchema>;
  loaded: boolean;
} {
  const [, setTick] = useState(0);
  useEffect(() => {
    if (cache) return;
    const fn = () => setTick((n) => n + 1);
    listeners.add(fn);
    void load();
    return () => {
      listeners.delete(fn);
    };
  }, []);
  const byFamily: Record<string, FacetSchema> = {};
  for (const f of cache ?? []) byFamily[f.name] = f;
  return { byFamily, loaded: cache !== undefined };
}

// formatFacetValue picks a sensible string projection for a single
// report-field value based on its declared kind. Lists join with
// commas, maps render as `key=value` pairs, ints stringify.
export function formatFacetValue(kind: string, value: unknown): string {
  if (value == null) return "";
  switch (kind) {
    case "string_list":
      return Array.isArray(value) ? value.filter(Boolean).join(", ") : String(value);
    case "string_map":
      if (value && typeof value === "object" && !Array.isArray(value)) {
        return Object.entries(value as Record<string, unknown>)
          .map(([k, v]) => `${k}=${v}`)
          .join(" ");
      }
      return "";
    case "int":
      return String(value);
    case "string":
    default:
      return typeof value === "string" ? value : String(value);
  }
}
