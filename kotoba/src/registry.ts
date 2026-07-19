/**
 * threat-intelligence kotoba — IOC registry (slice 1, 4/4 canonical).
 *
 *   registerIndicator — register an IOC (rkey={type}_{djb2(value)}, idempotent).
 *                       Per-type syntactic validation; confidence 0–1000 permille.
 *   getIndicator      — by (type, value).
 *   listIndicators    — cursor + type/tlp/source/minConfidence filter.
 *   coverage          — counts by type / tlp / source.
 *
 * Replaces vendor createKyselyDb()/vertex_threat_* with AT PDS records (no RW).
 * Published indicator data → 3-axis clean.
 */

import type { Etzhayyim } from "@etzhayyim/sdk";
import {
  indicatorDid,
  indicatorRkey,
  isValidIndicator,
  normalizeIndicator,
  type CoverageInput,
  type CoverageOutput,
  type GetIndicatorInput,
  type GetIndicatorOutput,
  type IndicatorRecord,
  type IndicatorType,
  type IndicatorView,
  type ListIndicatorsInput,
  type ListIndicatorsOutput,
  type RegisterIndicatorInput,
  type RegisterIndicatorOutput,
  type Tlp,
} from "./types.js";

const IOC_COLLECTION = "com.etzhayyim.apps.threatIntelligence.indicator";

const PAGE_LIMIT = 100;
const DEFAULT_MAX_SCAN = 10_000;

function clampPermille(n: number | undefined, fallback: number): number {
  if (typeof n !== "number" || Number.isNaN(n)) return fallback;
  return Math.max(0, Math.min(1000, Math.round(n)));
}

export async function registerIndicator(
  e: Etzhayyim,
  input: RegisterIndicatorInput
): Promise<RegisterIndicatorOutput> {
  if (!input.indicatorType || !input.value) {
    return { status: "rejected", error: "missingRequiredFields" };
  }
  if (!isValidIndicator(input.indicatorType, input.value)) {
    return { status: "rejected", error: "invalidIndicator" };
  }
  const value = normalizeIndicator(input.indicatorType, input.value);

  const rkey = indicatorRkey(input.indicatorType, value);
  const existing = await e
    .read<IndicatorRecord>({ collection: IOC_COLLECTION, rkey })
    .catch(() => ({ records: [] }));
  if (existing.records[0]?.value) {
    return {
      status: "alreadyExists",
      indicatorUri: existing.records[0].uri,
      did: existing.records[0].value.did,
      value,
    };
  }

  const did = indicatorDid(input.indicatorType, value);
  const now = new Date().toISOString();
  const record: IndicatorRecord = {
    did,
    indicatorType: input.indicatorType,
    value,
    confidencePermille: clampPermille(input.confidencePermille, 500),
    tlp: input.tlp ?? "amber",
    source: input.source,
    firstSeen: input.firstSeen,
    lastSeen: input.lastSeen,
    tags: input.tags,
    description: input.description,
    collectedAt: now,
    createdAt: now,
  };
  const receipt = await e.write({
    collection: IOC_COLLECTION,
    record: record as unknown as Record<string, unknown>,
    rkey,
  });
  return { status: "registered", indicatorUri: receipt.uri, did, value };
}

export async function getIndicator(
  e: Etzhayyim,
  input: GetIndicatorInput
): Promise<GetIndicatorOutput> {
  if (!input.indicatorType || !input.value) {
    return { error: "missingTypeOrValue" };
  }
  if (!isValidIndicator(input.indicatorType, input.value)) {
    return { error: "invalidIndicator" };
  }
  const resp = await e
    .read<IndicatorRecord>({
      collection: IOC_COLLECTION,
      rkey: indicatorRkey(input.indicatorType, input.value),
    })
    .catch(() => ({ records: [] }));
  const r = resp.records[0];
  if (!r) return { error: "notFound" };
  return { indicator: { ...r.value, indicatorUri: r.uri } };
}

export async function listIndicators(
  e: Etzhayyim,
  input: ListIndicatorsInput = {}
): Promise<ListIndicatorsOutput> {
  const limit = Math.min(input.limit ?? 50, 200);
  const resp = await e.read<IndicatorRecord>({
    collection: IOC_COLLECTION,
    cursor: input.cursor,
    limit,
  });
  const items: IndicatorView[] = resp.records
    .filter((r) => {
      const v = r.value;
      if (input.indicatorType && v.indicatorType !== input.indicatorType) return false;
      if (input.tlp && v.tlp !== input.tlp) return false;
      if (input.source && v.source !== input.source) return false;
      if (
        typeof input.minConfidencePermille === "number" &&
        v.confidencePermille < input.minConfidencePermille
      ) {
        return false;
      }
      return true;
    })
    .map((r) => ({ ...r.value, indicatorUri: r.uri }));
  return { items, cursor: resp.cursor, total: items.length };
}

export async function coverage(
  e: Etzhayyim,
  input: CoverageInput = {}
): Promise<CoverageOutput> {
  const maxScan = Math.min(input.maxScan ?? DEFAULT_MAX_SCAN, DEFAULT_MAX_SCAN);
  let cursor: string | undefined;
  let scanned = 0;
  const byType: Record<string, number> = {};
  const byTlp: Record<string, number> = {};
  const bySource: Record<string, number> = {};
  while (scanned < maxScan) {
    const page = await e.read<IndicatorRecord>({
      collection: IOC_COLLECTION,
      cursor,
      limit: PAGE_LIMIT,
    });
    for (const r of page.records) {
      if (scanned >= maxScan) break;
      const v = r.value;
      byType[v.indicatorType as IndicatorType] =
        (byType[v.indicatorType as IndicatorType] ?? 0) + 1;
      byTlp[v.tlp as Tlp] = (byTlp[v.tlp as Tlp] ?? 0) + 1;
      if (v.source) bySource[v.source] = (bySource[v.source] ?? 0) + 1;
      scanned += 1;
    }
    if (scanned >= maxScan || !page.cursor || page.records.length < PAGE_LIMIT) {
      break;
    }
    cursor = page.cursor;
  }
  return { total: scanned, byType, byTlp, bySource, truncated: scanned >= maxScan };
}
