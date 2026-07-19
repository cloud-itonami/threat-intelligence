/**
 * threat-intelligence kotoba — record types.
 *
 * Per ADR-2605203000 Option B (PDS XRPC). Public IOC (Indicator of Compromise)
 * registry — IPs / domains / URLs / file hashes / CVEs with confidence + TLP.
 * Published, non-PII threat indicators → 3-axis clean. ADR-2605172000 kotoba.
 *
 * Identity hierarchy:
 *   did:web:threat-intelligence.etzhayyim.com                        — controller
 *   did:web:threat-intelligence.etzhayyim.com:ioc:{type}:{key}       — an indicator
 */

export const TI_DID_PREFIX =
  "did:web:threat-intelligence.etzhayyim.com:" as const;

export type IndicatorType =
  | "ipv4"
  | "ipv6"
  | "domain"
  | "url"
  | "md5"
  | "sha1"
  | "sha256"
  | "email"
  | "cve";

/** Traffic Light Protocol sharing class. */
export type Tlp = "white" | "green" | "amber" | "red";

export interface IndicatorRecord {
  did: string;
  indicatorType: IndicatorType;
  /** Normalized indicator value (canonical key for the type). */
  value: string;
  /** Confidence 0–1000 permille (AT Lexicon has no float). */
  confidencePermille: number;
  tlp: Tlp;
  source?: string;
  firstSeen?: string;
  lastSeen?: string;
  tags?: string[];
  description?: string;
  collectedAt: string;
  createdAt: string;
}

export interface IndicatorView extends IndicatorRecord {
  indicatorUri: string;
}

export interface RegisterIndicatorInput {
  indicatorType: IndicatorType;
  value: string;
  confidencePermille?: number;
  tlp?: Tlp;
  source?: string;
  firstSeen?: string;
  lastSeen?: string;
  tags?: string[];
  description?: string;
}

export interface RegisterIndicatorOutput {
  status: "registered" | "alreadyExists" | "rejected";
  indicatorUri?: string;
  did?: string;
  value?: string;
  error?: string;
}

export interface GetIndicatorInput {
  indicatorType: IndicatorType;
  value: string;
}

export interface GetIndicatorOutput {
  indicator?: IndicatorView;
  error?: string;
}

export interface ListIndicatorsInput {
  indicatorType?: IndicatorType;
  tlp?: Tlp;
  source?: string;
  minConfidencePermille?: number;
  limit?: number;
  cursor?: string;
}

export interface ListIndicatorsOutput {
  items: IndicatorView[];
  cursor?: string;
  total: number;
}

export interface CoverageInput {
  maxScan?: number;
}

export interface CoverageOutput {
  total?: number;
  byType?: Record<string, number>;
  byTlp?: Record<string, number>;
  bySource?: Record<string, number>;
  truncated?: boolean;
  error?: string;
}

// ─── Validation + normalization ─────────────────────────────────────

const RE: Record<IndicatorType, RegExp> = {
  ipv4: /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/,
  ipv6: /^(?=.*:)[0-9a-f:]+$/i,
  domain: /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i,
  url: /^https?:\/\/[^\s]+$/i,
  md5: /^[a-f0-9]{32}$/i,
  sha1: /^[a-f0-9]{40}$/i,
  sha256: /^[a-f0-9]{64}$/i,
  email: /^[^@\s]+@[^@\s]+\.[^@\s]+$/,
  cve: /^CVE-\d{4}-\d{4,}$/i,
};

/** Lowercase the host-/case-insensitive types; uppercase CVE; trim. */
export function normalizeIndicator(type: IndicatorType, value: string): string {
  const v = value.trim();
  if (type === "cve") return v.toUpperCase();
  if (type === "domain" || type === "email" || type === "md5" || type === "sha1" || type === "sha256") {
    return v.toLowerCase();
  }
  return v;
}

/** Per-type syntactic validation (ipv4 octets are range-checked). */
export function isValidIndicator(type: IndicatorType, value: string): boolean {
  const v = normalizeIndicator(type, value);
  const m = RE[type].exec(v);
  if (!m) return false;
  if (type === "ipv4") {
    return [m[1], m[2], m[3], m[4]].every((o) => Number(o) >= 0 && Number(o) <= 255);
  }
  return true;
}

/** djb2 hash → 8-hex, for a stable rkey/DID segment from an arbitrary value. */
export function valueKey(value: string): string {
  let h = 5381;
  for (let i = 0; i < value.length; i++) {
    h = ((h << 5) + h + value.charCodeAt(i)) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

export function indicatorDid(type: IndicatorType, value: string): string {
  return `${TI_DID_PREFIX}ioc:${type}:${valueKey(normalizeIndicator(type, value))}`;
}

export function indicatorRkey(type: IndicatorType, value: string): string {
  return `${type}_${valueKey(normalizeIndicator(type, value))}`;
}
