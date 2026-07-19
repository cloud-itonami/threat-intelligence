/**
 * threat-intelligence kotoba — barrel.
 *
 * Per ADR-2605203000 Option B Phase E reference impl. Public IOC registry on
 * the etzhayyim substrate (AT PDS records; no RW).
 *
 * Slice 1: 4 of 4 canonical lexicons ported.
 *   registerIndicator + getIndicator + listIndicators + coverage
 */

export * from "./types.js";
export {
  registerIndicator,
  getIndicator,
  listIndicators,
  coverage,
} from "./registry.js";
