import { afterEach, describe, expect, it, vi } from "vitest";
import { cvssBaseScore } from "../cvss";
import { normalizeOsvVulnerability, parseOsvScannerJson, queryOsvApi } from "../osv";
import type { PackageManifest } from "../packageDetection";

const manifest: PackageManifest = { name: "fixture", packageManager: "npm", ecosystem: "npm", dependencies: { example: "2.1.0" }, devDependencies: {}, optionalDependencies: {}, scripts: {}, manifestPath: "/fixture/package.json", stack: [] };
const affected = (name: string, events: Array<{ introduced?: string; fixed?: string }>, ecosystem = "npm") => ({ package: { name, ecosystem }, ranges: [{ type: ecosystem === "npm" ? "SEMVER" : "ECOSYSTEM", events }] });
afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

describe("OSV fix boundaries", () => {
  it("never uses unrelated packages, ecosystems, git hashes, or older branches as fixes", () => {
    const finding = normalizeOsvVulnerability({ id: "OSV-1", affected: [
      affected("other", [{ introduced: "0" }, { fixed: "1.0.1" }]),
      affected("example", [{ introduced: "0" }, { fixed: "2.1.1" }], "PyPI"),
      affected("example", [{ introduced: "0" }, { fixed: "1.9.0" }, { introduced: "2.0.0" }, { fixed: "2.2.0" }]),
      { package: { name: "example", ecosystem: "npm" }, ranges: [{ type: "GIT", events: [{ introduced: "0" }, { fixed: "0123456789" }] }] }
    ] }, "example", "2.1.0", "direct");
    expect(finding.fixedVersion).toBe("2.2.0");
    expect(finding.affectedRanges.join()).not.toContain("1.0.1");
  });
  it("does not recommend a fix still affected by another interval", () => {
    const finding = normalizeOsvVulnerability({ id: "OSV-1", affected: [
      affected("example", [{ introduced: "0" }, { fixed: "2.2.0" }]),
      affected("example", [{ introduced: "2.0.0" }, { fixed: "2.3.0" }])
    ] }, "example", "2.1.0", "direct");
    expect(finding.fixedVersion).toBe("2.3.0");
  });
  it("leaves unknown, open-ended and opaque fixes for manual review", () => {
    for (const entries of [[], [affected("example", [{ introduced: "0" }])], [affected("example", [{ introduced: "0" }, { fixed: "2.2.0" }]), affected("example", [{ introduced: "opaque" }])]]) {
      expect(normalizeOsvVulnerability({ id: "OSV-1", affected: entries }, "example", "2.1.0", "direct").fixedVersion).toBeUndefined();
    }
  });
  it("normalizes PyPI package names and compares numeric releases without semver coercion", () => {
    expect(normalizeOsvVulnerability({ id: "OSV-1", affected: [affected("Some_Package", [{ introduced: "0" }, { fixed: "2.10" }], "PyPI")] }, "some-package", "2.9", "direct", "PyPI").fixedVersion).toBe("2.10");
  });
});

describe("CVSS scoring", () => {
  it.each([
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
    ["CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5]
  ])("scores %s", (vector, expected) => expect(cvssBaseScore(vector)).toBe(expected));
  it.each(["CVSS:4.0/AV:N", "CVSS:3.1/AV:N", "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]) ("rejects incomplete/unsupported vectors %s", (vector) => expect(cvssBaseScore(vector)).toBeUndefined());
  it("uses vectors, zero scores, and database severity labels", () => {
    const normalize = (fields: Parameters<typeof normalizeOsvVulnerability>[0]) => normalizeOsvVulnerability(fields, "example", "1.0.0", "direct").vulnerability;
    expect(normalize({ id: "OSV-1", severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] })).toMatchObject({ severity: "critical", cvssScore: 9.8 });
    expect(normalize({ id: "OSV-1", severity: [{ type: "CVSS_V3", score: "0" }] }).cvssScore).toBe(0);
    expect(normalize({ id: "OSV-1", database_specific: { severity: "MODERATE" } }).severity).toBe("medium");
  });
});

describe("OSV response completeness", () => {
  it.each([{}, { results: [] }, { results: [null] }, { results: [{ vulns: {} }] }, { results: [{ error: "upstream failed" }] }])("rejects incomplete batch %j", async (body) => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(body))));
    await expect(queryOsvApi(manifest)).rejects.toMatchObject({ code: "osv_response_invalid" });
  });
  it("accepts an explicit empty result per queried package", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ results: [{}] }))));
    expect(await queryOsvApi(manifest)).toEqual([]);
  });
  it("follows per-package pagination and deduplicates IDs", async () => {
    const calls: any[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (url.includes("/vulns/")) return new Response(JSON.stringify({ id: url.split("/").at(-1) }));
      const body = JSON.parse(String(init?.body)); calls.push(body);
      return new Response(JSON.stringify(calls.length === 1 ? { results: [{ vulns: [{ id: "OSV-1" }], next_page_token: "next" }, {}] } : { results: [{ vulns: [{ id: "OSV-1" }, { id: "OSV-2" }] }] }));
    }));
    expect(await queryOsvApi({ ...manifest, dependencies: { example: "2.1.0", second: "1.0.0" } })).toHaveLength(2);
    expect(calls[1].queries).toEqual([{ package: { name: "example", ecosystem: "npm" }, version: "2.1.0", page_token: "next" }]);
  });
  it("rejects looping pagination", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ results: [{ next_page_token: "same" }] }))));
    await expect(queryOsvApi(manifest)).rejects.toMatchObject({ code: "osv_pagination_failed" });
  });
  it("keeps known findings when advisory hydration fails", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => url.includes("/vulns/") ? new Response("error", { status: 503 }) : new Response(JSON.stringify({ results: [{ vulns: [{ id: "OSV-1" }] }] }))));
    expect(await queryOsvApi(manifest)).toMatchObject([{ vulnerability: { id: "OSV-1", severity: "unknown" } }]);
  });
  it("rejects operational scanner output rather than returning a clean scan", () => {
    for (const raw of ["{}", "null", '{"error":"failure"}', '{"results":[{}]}', '{"results":[],"errors":["failed"]}']) expect(() => parseOsvScannerJson(raw, new Set())).toThrow();
    expect(parseOsvScannerJson('{"results":[]}', new Set())).toEqual([]);
  });
  it("rejects unsupported version specifiers before network requests", async () => {
    const fetcher = vi.fn(); vi.stubGlobal("fetch", fetcher);
    await expect(queryOsvApi({ ...manifest, dependencies: { example: "workspace:*" } })).rejects.toMatchObject({ code: "osv_version_unresolved" });
    expect(fetcher).not.toHaveBeenCalled();
  });
});
