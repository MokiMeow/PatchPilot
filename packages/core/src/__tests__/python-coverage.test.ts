import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { readPythonManifest } from "../packageDetection";
import { normalizeOsvVulnerability } from "../osv";

describe("Python manifest coverage", () => {
  it.each(["requests", "-r other.txt", "requests>=1.0,<2.0", "requests==1.*", "git+https://example.invalid/repo", "-e .", "__proto__==1.0", ".invalid==1.0", "invalid-==1.0"])("rejects unresolved entries instead of silently scanning zero dependencies: %s", (line) => {
    const root = mkdtempSync(path.join(os.tmpdir(), "pp-requirements-"));
    try { writeFileSync(path.join(root, "requirements.txt"), line); expect(() => readPythonManifest(root)).toThrow(/Unsupported requirements entry/); }
    finally { rmSync(root, { recursive: true, force: true }); }
  });
  it.each([
    'requests==2.0 ; python_version < "3.10"\nrequests==2.32 ; python_version >= "3.10"',
    "Some_Package==1.0\nsome-package==2.0",
    "some..package==1.0\nSOME_package==2.0",
    "requests==2.0\nrequests==2.0"
  ])("rejects repeated canonical packages rather than overwriting coverage: %s", (requirements) => {
    const root = mkdtempSync(path.join(os.tmpdir(), "pp-requirements-"));
    try {
      writeFileSync(path.join(root, "requirements.txt"), requirements);
      expect(() => readPythonManifest(root)).toThrow(/Repeated Python package requirement/);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
  it("reads extras and markers without changing the package identity", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "pp-requirements-"));
    try {
      writeFileSync(path.join(root, "requirements.txt"), '# comment\nrequests[security]==2.30.0 ; python_version >= "3.10"\nflask===2.0.0\n');
      expect(readPythonManifest(root)?.dependencies).toEqual({ requests: "2.30.0", flask: "2.0.0" });
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
  it("does not propose a release listed as an equivalent affected Python version", () => {
    const finding = normalizeOsvVulnerability({ id: "OSV-1", affected: [{
      package: { name: "example", ecosystem: "PyPI" }, versions: ["2.0.0"],
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.0" }] }]
    }] }, "example", "1.0", "direct", "PyPI");
    expect(finding.fixedVersion).toBeUndefined();
  });
  it.each(["v2.0", "0!2.0", "2.0rc1", "opaque"])("keeps findings but suppresses fixes when affected versions are unsupported: %s", (version) => {
    const finding = normalizeOsvVulnerability({ id: "OSV-1", affected: [{
      package: { name: "example", ecosystem: "PyPI" }, versions: [version],
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.0" }] }]
    }] }, "example", "1.0", "direct", "PyPI");
    expect(finding.vulnerability.id).toBe("OSV-1");
    expect(finding.fixedVersion).toBeUndefined();
  });
  it("compares arbitrary-size Python release components without rounding", () => {
    const finding = normalizeOsvVulnerability({ id: "OSV-1", affected: [{
      package: { name: "example", ecosystem: "PyPI" },
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.9007199254740993" }] }]
    }] }, "example", "1.9007199254740992", "direct", "PyPI");
    expect(finding.fixedVersion).toBe("1.9007199254740993");
  });
});
