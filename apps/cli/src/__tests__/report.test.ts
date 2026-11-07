import { describe, expect, it } from "vitest";
import { groupByPackage, type Group } from "../report";

const finding = (fixedVersion: string | null): Omit<Group, "count"> => ({
  package: "example", ecosystem: "npm", currentVersion: "1.0.0",
  severity: "high", fixedVersion, reachability: "unknown"
});

describe("Grouped advisory fix safety", () => {
  it.each([
    ["1.1.0", "2.0.0", "1.1.0"],
    ["2.0.0", "1.1.0", "1.1.0"],
    ["1.1.0", "1.1.0", "2.0.0"]
  ])("does not assume the largest target clears reintroductions: %s, %s, %s", (...targets) => {
    // Advisory A is fixed at 1.1.0 but reintroduced at 2.0.0. Advisory B is
    // fixed at 2.0.0. A maximum would incorrectly present 2.0.0 as a shared fix.
    expect(groupByPackage(targets.map(finding))).toMatchObject([{ fixedVersion: null, count: 3 }]);
  });
  it.each([
    [null, "1.1.0", "1.1.0"],
    ["1.1.0", null, "1.1.0"],
    ["1.1.0", "1.1.0", null]
  ])("keeps manual review when any advisory lacks a fix: %s, %s, %s", (...targets) => {
    expect(groupByPackage(targets.map(finding))[0]?.fixedVersion).toBeNull();
  });
  it("preserves a target only when all advisories agree", () => {
    expect(groupByPackage([finding("1.1.0"), finding("1.1.0")])).toMatchObject([{ fixedVersion: "1.1.0", count: 2 }]);
  });
  it("never merges different ecosystems or installed versions", () => {
    expect(groupByPackage([
      finding("1.1.0"), { ...finding("2.0.0"), ecosystem: "PyPI" },
      { ...finding("2.0.0"), currentVersion: "1.9.0" }
    ])).toHaveLength(3);
  });
});
