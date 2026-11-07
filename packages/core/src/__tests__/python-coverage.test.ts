import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { readPythonManifest } from "../packageDetection";
import { normalizeOsvVulnerability } from "../osv";

describe("Python manifest coverage", () => {
  it.each(["requests", "-r other.txt", "requests>=1.0,<2.0", "requests==1.*", "git+https://example.invalid/repo", "-e ."])("rejects unresolved entries instead of silently scanning zero dependencies: %s", (line) => {
    const root = mkdtempSync(path.join(os.tmpdir(), "pp-requirements-"));
    try { writeFileSync(path.join(root, "requirements.txt"), line); expect(() => readPythonManifest(root)).toThrow(/Unsupported requirements entry/); }
    finally { rmSync(root, { recursive: true, force: true }); }
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
});
