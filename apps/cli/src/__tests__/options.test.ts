import { describe, expect, it } from "vitest";
import { parseScanOptions, severityExitCode } from "../options";

describe("CLI policy flags", () => {
  it.each([[], ["."], ["--json", "."], ["--fail-on", "HIGH", "."]].map((args) => [args]))("parses %j", (args) => {
    expect(() => parseScanOptions(args)).not.toThrow();
  });
  it.each([["--fail-on"], ["--fail-on", "hgh"], ["--fail-on", "unknown"], ["--fail-on", "toString"], ["--wat"], ["a", "b"], ["--fail-on", "high", "--fail-on", "low"]].map((args) => [args]))("rejects unsafe arguments %j", (args) => {
    expect(() => parseScanOptions(args)).toThrow();
  });
  it("does not consume a project named high as a flag value", () => {
    expect(parseScanOptions(["high", "--fail-on", "high"])).toEqual({ target: "high", failOn: "high", json: false });
  });
  it("uses distinct violation and incomplete exit codes", () => {
    expect(severityExitCode(["critical"], "high")).toBe(1);
    expect(severityExitCode(["unknown"], "high")).toBe(2);
    expect(severityExitCode(["low"], "high")).toBe(0);
    expect(severityExitCode([], "high")).toBe(0);
    expect(severityExitCode(["unknown"])).toBe(0);
  });
});
