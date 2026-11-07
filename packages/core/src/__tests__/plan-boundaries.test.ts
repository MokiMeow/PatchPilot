import { describe, expect, it } from "vitest";
import { parseRemediationPlan } from "../agentProviders";

const expected = { packageName: "example", fromVersion: "1.0.0", fixedVersion: "1.1.0" };
const plan = { action: "update_dependency", ecosystem: "npm", file: "package.json", packageName: "example", fromVersion: "1.0.0", toVersion: "1.1.0", summary: "Use the advisory target." };

describe("Remediation version boundaries", () => {
  it.each(["^1.1.0", ">=1.1.0", "https://example.invalid/pkg-1.1.0.tgz", "npm:other@1.1.0", "1.1", "latest"])("rejects coercible or unresolved model targets: %s", (toVersion) => {
    expect(() => parseRemediationPlan(JSON.stringify({ ...plan, toVersion }), expected)).toThrow(/invalid target version/);
  });
  it("rejects a later same-major release that could reintroduce the vulnerability", () => {
    expect(() => parseRemediationPlan(JSON.stringify({ ...plan, toVersion: "1.2.0" }), expected)).toThrow(/differs from the advisory fix/);
  });
  it("requires an exact known fix rather than accepting unverified upgrades", () => {
    expect(() => parseRemediationPlan(JSON.stringify(plan), { ...expected, fixedVersion: undefined })).toThrow(/exact validated advisory fix/);
  });
  it("rejects plans based on a different source version", () => {
    expect(() => parseRemediationPlan(JSON.stringify({ ...plan, fromVersion: "0.9.0" }), expected)).toThrow(/source version/);
  });
  it("returns the concrete advisory version rather than raw model text", () => {
    expect(parseRemediationPlan(JSON.stringify({ ...plan, toVersion: "v1.1.0" }), expected).toVersion).toBe("1.1.0");
  });
});
