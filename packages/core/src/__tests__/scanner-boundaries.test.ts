import { writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runProjectScanners, scanContainerImage } from "../scanners";

vi.mock("node:child_process", () => ({ spawnSync: vi.fn() }));
vi.mock("../env", async (original) => ({ ...await original<typeof import("../env")>(), commandExists: () => true }));

afterEach(() => { vi.resetAllMocks(); vi.unstubAllEnvs(); });
function tool(report: string | undefined, status = 0, error?: Error) {
  vi.mocked(spawnSync).mockImplementation((_command, args: any) => {
    if (args.includes("--version")) return { status: 0, stdout: "test-tool 1.0", stderr: "" } as any;
    const reportIndex = args.indexOf("--report-path");
    if (reportIndex >= 0 && report !== undefined) writeFileSync(args[reportIndex + 1], report);
    return { status, stdout: report ?? "", stderr: "", error } as any;
  });
}
function scan(category: "secret" | "sast" | "container") {
  return runProjectScanners(process.cwd(), undefined, { categories: [category] }).find(r => r.scanner === ({secret:"gitleaks",sast:"semgrep",container:"trivy"}[category]))!;
}
describe("external scanner completion boundaries", () => {
  it.each([undefined, "bad json", "{}", "null"])("does not mark missing or invalid Gitleaks reports clean: %s", report => {
    tool(report); expect(scan("secret")).toMatchObject({ status: "error", complete: false });
  });
  it("distinguishes Gitleaks leak exit from operational errors and retains partial findings", () => {
    tool('[{"RuleID":"test","Secret":"private-value"}]', 10);
    expect(scan("secret")).toMatchObject({status:"completed",complete:true, findings:[{scanner:"gitleaks"}]});
    tool('[{"RuleID":"test"}]', 1);
    expect(scan("secret")).toMatchObject({status:"error",complete:false, findings:[{scanner:"gitleaks"}]});
    tool('[]', 10); expect(scan("secret").complete).toBe(false);
    tool('[]'); expect(scan("secret").complete).toBe(true);
  });
  it.each(["{", "null", "{}", '{"results":{}}'])("rejects malformed Semgrep reports: %s", report => {
    tool(report); expect(scan("sast").complete).toBe(false);
  });
  it("retains Semgrep findings when analysis errors or failure exits make coverage partial", () => {
    tool('{"results":[{"check_id":"test"}],"errors":[{"message":"timeout"}]}');
    expect(scan("sast")).toMatchObject({status:"error",complete:false,findings:[{scanner:"semgrep"}]});
    tool('{"results":[]}', 2); expect(scan("sast").complete).toBe(false);
    tool('{"results":[],"errors":[]}'); expect(scan("sast").complete).toBe(true);
  });
  it.each(["{", "null", "{}", '{"Results":{}}'])("rejects malformed Trivy reports for filesystem and images: %s", report => {
    tool(report); expect(scan("container").complete).toBe(false);
    expect(scanContainerImage("test:local").complete).toBe(false);
  });
  it.each(["Vulnerabilities", "Misconfigurations", "Secrets", "Licenses"])("rejects invalid nested Trivy %s collections", key => {
    for (const value of [null, "invalid", {}, [null], ["invalid"]]) {
      tool(JSON.stringify({Results:[{[key]:value}]}));
      expect(scan("container").complete).toBe(false);
      expect(scanContainerImage("test:local").complete).toBe(false);
    }
  });
  it("rejects malformed Semgrep nested fields", () => {
    for (const result of [{start:null}, {start:[]}, {extra:"invalid"}, {extra:{metadata:[]}}]) {
      tool(JSON.stringify({results:[result]})); expect(scan("sast").complete).toBe(false);
    }
  });
  it("accepts empty Trivy reports but not failed processes or timeouts", () => {
    for (const report of ['{"SchemaVersion":2}', '{"Results":[]}']) {
      tool(report); expect(scan("container").complete).toBe(true);
      expect(scanContainerImage("test:local").complete).toBe(true);
    }
    tool('{"Results":[]}', 1); expect(scan("container").complete).toBe(false);
    tool('{"Results":[]}', 0, Object.assign(new Error("timeout"), {code:"ETIMEDOUT"}));
    expect(scanContainerImage("test:local").complete).toBe(false);
  });
});
