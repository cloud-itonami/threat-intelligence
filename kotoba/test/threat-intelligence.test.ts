import { describe, it, expect, beforeEach } from "vitest";
import { MockEtzhayyim } from "@etzhayyim/sdk-mock";
import {
  registerIndicator,
  getIndicator,
  listIndicators,
  coverage,
  isValidIndicator,
  normalizeIndicator,
  indicatorRkey,
} from "../src/index.js";

describe("threat-intelligence kotoba", () => {
  let e: any;
  beforeEach(() => {
    e = new MockEtzhayyim({ did: "did:web:threat-intelligence.etzhayyim.com" });
  });

  describe("validation + normalization", () => {
    it("validates per type", () => {
      expect(isValidIndicator("ipv4", "8.8.8.8")).toBe(true);
      expect(isValidIndicator("ipv4", "999.1.1.1")).toBe(false);
      expect(isValidIndicator("domain", "evil.example.com")).toBe(true);
      expect(isValidIndicator("sha256", "a".repeat(64))).toBe(true);
      expect(isValidIndicator("sha256", "a".repeat(63))).toBe(false);
      expect(isValidIndicator("cve", "CVE-2026-12345")).toBe(true);
      expect(isValidIndicator("cve", "CVE-26-1")).toBe(false);
      expect(isValidIndicator("url", "https://evil.test/x")).toBe(true);
      expect(isValidIndicator("email", "a@b.co")).toBe(true);
    });
    it("normalizes case for case-insensitive types", () => {
      expect(normalizeIndicator("domain", "Evil.Example.COM")).toBe("evil.example.com");
      expect(normalizeIndicator("sha256", "ABC")).toBe("abc");
      expect(normalizeIndicator("cve", "cve-2026-1234")).toBe("CVE-2026-1234");
    });
    it("rkey is stable + value-derived", () => {
      const a = indicatorRkey("domain", "Evil.Example.com");
      const b = indicatorRkey("domain", "evil.example.com");
      expect(a).toBe(b); // normalization makes them identical
      expect(a.startsWith("domain_")).toBe(true);
    });
  });

  describe("registerIndicator", () => {
    it("registers a valid IOC (defaults: amber, 500‰)", async () => {
      const r = await registerIndicator(e, { indicatorType: "ipv4", value: "8.8.8.8" });
      expect(r.status).toBe("registered");
      const got = await getIndicator(e, { indicatorType: "ipv4", value: "8.8.8.8" });
      expect(got.indicator?.tlp).toBe("amber");
      expect(got.indicator?.confidencePermille).toBe(500);
    });
    it("clamps confidence to 0–1000", async () => {
      await registerIndicator(e, {
        indicatorType: "domain",
        value: "evil.test",
        confidencePermille: 5000,
      });
      const got = await getIndicator(e, { indicatorType: "domain", value: "evil.test" });
      expect(got.indicator?.confidencePermille).toBe(1000);
    });
    it("is idempotent on normalized (type, value)", async () => {
      await registerIndicator(e, { indicatorType: "domain", value: "Evil.Test" });
      const again = await registerIndicator(e, { indicatorType: "domain", value: "evil.test" });
      expect(again.status).toBe("alreadyExists");
    });
    it("rejects an invalid indicator", async () => {
      const r = await registerIndicator(e, { indicatorType: "ipv4", value: "not-an-ip" });
      expect(r.status).toBe("rejected");
      expect(r.error).toBe("invalidIndicator");
    });
  });

  describe("list + coverage", () => {
    beforeEach(async () => {
      await registerIndicator(e, {
        indicatorType: "ipv4",
        value: "8.8.8.8",
        tlp: "green",
        source: "feedA",
        confidencePermille: 800,
      });
      await registerIndicator(e, {
        indicatorType: "domain",
        value: "evil.test",
        tlp: "red",
        source: "feedA",
        confidencePermille: 300,
      });
    });
    it("filters by type", async () => {
      const ips = await listIndicators(e, { indicatorType: "ipv4" });
      expect(ips.total).toBe(1);
    });
    it("filters by minConfidence", async () => {
      const hi = await listIndicators(e, { minConfidencePermille: 500 });
      expect(hi.total).toBe(1);
      expect(hi.items[0].indicatorType).toBe("ipv4");
    });
    it("coverage aggregates by type/tlp/source", async () => {
      const cov = await coverage(e);
      expect(cov.total).toBe(2);
      expect(cov.byType?.ipv4).toBe(1);
      expect(cov.byTlp?.red).toBe(1);
      expect(cov.bySource?.feedA).toBe(2);
    });
  });
});
