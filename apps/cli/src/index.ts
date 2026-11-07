#!/usr/bin/env node
/**
 * PatchPilot CLI — a thin, standalone scanner over @patchpilot/core.
 *
 *   patchpilot scan [path]     Scan a project folder for vulnerable deps (npm + PyPI)
 *   patchpilot --help
 *
 * It queries the live OSV database and tags each finding with the reachability
 * (VEX-lite) signal — so you fix what's actually imported first. Real results
 * only; an incomplete or failed scan exits non-zero.
 */
import path from "node:path";
import { parseScanOptions, severityExitCode, SEVERITY_RANK } from "./options";
import { detectManifests } from "@patchpilot/core";
import { queryOsvFindings } from "@patchpilot/core";
import { collectFirstPartyImports, reachabilityForFinding } from "@patchpilot/core";

const C = {
  reset: "\x1b[0m", dim: "\x1b[2m", bold: "\x1b[1m",
  orange: "\x1b[38;5;208m", red: "\x1b[31m", yellow: "\x1b[33m", green: "\x1b[32m", gray: "\x1b[90m"
};
const useColor = process.stdout.isTTY && process.env.NO_COLOR === undefined;
const c = (code: string, s: string) => (useColor ? code + s + C.reset : s);

const REACH_LABEL: Record<string, string> = {
  imported: "reachable", not_imported: "import not observed", indirect: "transitive", unknown: "unknown"
};
const SHORT_SEV: Record<string, string> = { critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW", unknown: "—" };

function usage(): void {
  console.log(`
${c(C.orange, "●")} ${c(C.bold, "PatchPilot CLI")} — supply-chain scanner (npm + PyPI)

${c(C.bold, "Usage")}
  patchpilot scan [path]        Scan a project folder (default: current directory)
  patchpilot --help             Show this help

${c(C.bold, "Options")}
  --json                        Output findings as JSON
  --fail-on <level>             Exit non-zero if a finding at/above this severity exists
                                (critical | high | medium | low). Default: never fail.

${c(C.bold, "Examples")}
  npx patchpilot-cli scan
  npx patchpilot-cli scan ./my-app --fail-on high
  patchpilot scan . --json > findings.json

Reachability: ${c(C.orange, "● reachable")} = imported in your source · ${c(C.gray, "○ import not observed / transitive")} = import signal only, not proof of safety.
Network/scanner errors exit 2, never a clean result. Unknown severity also exits 2 when --fail-on is set.
Manifest-only scans estimate versions and do not cover transitive dependencies.
`);
}

function sevColor(sev: string): string {
  if (sev === "critical" || sev === "high") return C.red;
  if (sev === "medium") return C.yellow;
  if (sev === "low") return C.gray;
  return C.gray;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv.includes("--help") || argv.includes("-h")) { usage(); process.exit(0); }
  if (argv[0] !== "scan") { console.error(c(C.red, `Unknown command: ${argv[0]}`)); usage(); process.exit(2); }

  const { json, failOn, target: requestedTarget } = parseScanOptions(argv.slice(1));
  const target = path.resolve(requestedTarget ?? process.cwd());

  if (!json) {
    console.error("");
    console.error(c(C.dim, `  $ patchpilot scan ${requestedTarget ?? "."}`));
    console.error(c(C.dim, `  Scanning ${target} via OSV…`));
  }

  const manifests = detectManifests(target);
  if (manifests.length === 0) {
    const msg = "No package.json or requirements.txt found. PatchPilot scans Node.js (npm) and Python (PyPI) projects.";
    if (json) console.log(JSON.stringify({ error: "unsupported_project", message: msg }, null, 2));
    else console.error(c(C.red, "  " + msg));
    process.exit(2);
  }

  const result = await queryOsvFindings(target, manifests);
  const imports = collectFirstPartyImports(target);

  let findings = result.findings.map((f) => {
    const reach = reachabilityForFinding(
      { packageName: f.packageName, ecosystem: f.ecosystem, dependencyType: f.dependencyType }, imports
    );
    const advisory = f.vulnerability.osvId ?? f.vulnerability.cveIds[0] ?? f.vulnerability.id;
    return {
      package: f.packageName, ecosystem: f.ecosystem, currentVersion: f.currentVersion,
      fixedVersion: f.fixedVersion ?? null,
      severity: (f.vulnerability.severity || "unknown").toLowerCase(),
      advisory, dependencyType: f.dependencyType,
      reachability: reach.status, reachabilityNote: reach.note
    };
  });

  // Reachable first, then by severity, then package name.
  findings.sort((a, b) => {
    const ra = a.reachability === "imported" ? 1 : 0, rb = b.reachability === "imported" ? 1 : 0;
    if (ra !== rb) return rb - ra;
    const sd = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    if (sd !== 0) return sd;
    return a.package.localeCompare(b.package);
  });

  if (json) {
    console.log(JSON.stringify({ target, scanner: result.scanner, scanConfidence: result.scanConfidence, count: findings.length, findings }, null, 2));
  } else {
    const groups = groupByPackage(findings);
    printReport(groups, findings.length, result.scanner);
    if (result.scanConfidence === "direct_manifest_only") console.log(c(C.yellow, "  Coverage: direct manifest dependencies only; versions are estimates, transitive dependencies were not scanned.\n"));
  }

  const exitCode = severityExitCode(findings.map((finding) => finding.severity), failOn);
  if (exitCode === 2) console.error("Severity gate is incomplete: at least one advisory has unknown severity. Review it before accepting this scan.");
  process.exit(exitCode);
}

interface Group {
  package: string; ecosystem: string; currentVersion: string; severity: string;
  fixedVersion: string | null; reachability: string; count: number;
}

/** Groups per-advisory findings into one row per package. */
function groupByPackage(findings: Array<Record<string, any>>): Group[] {
  const map = new Map<string, Group>();
  for (const f of findings) {
    const key = `${f.ecosystem}:${f.package}@${f.currentVersion}`;
    const g = map.get(key);
    if (!g) {
      map.set(key, { package: f.package, ecosystem: f.ecosystem, currentVersion: f.currentVersion, severity: f.severity,
        fixedVersion: f.fixedVersion, reachability: f.reachability, count: 1 });
    } else {
      if ((SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[g.severity] ?? 0)) g.severity = f.severity;
      // Different advisory targets are not necessarily mutually safe after reintroductions.
      if (g.fixedVersion !== f.fixedVersion) g.fixedVersion = null;
      g.count += 1;
    }
  }
  return [...map.values()].sort((a, b) => {
    const r = (b.reachability === "imported" ? 1 : 0) - (a.reachability === "imported" ? 1 : 0);
    if (r) return r;
    const s = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    return s || a.package.localeCompare(b.package);
  });
}

function printReport(groups: Group[], advisoryCount: number, scanner: string): void {
  if (groups.length === 0) {
    console.log("\n" + c(C.green, "  ✓ No known vulnerable dependencies found.") + c(C.dim, `  (scanner: ${scanner})\n`));
    return;
  }
  console.log("");
  console.log("  " + c(C.bold, `${groups.length} vulnerable package${groups.length === 1 ? "" : "s"}`)
    + c(C.dim, `  ·  ${advisoryCount} advisories  ·  scanner: ${scanner}`));
  console.log("");
  for (const g of groups) {
    const sev = (SHORT_SEV[g.severity] ?? "·").padEnd(4);
    const pkg = c(C.bold, g.package) + c(C.dim, `@${g.currentVersion}`);
    const fix = g.fixedVersion ? c(C.green, `→ ${g.fixedVersion} (advisory target; verify availability)`) : c(C.dim, "manual review");
    const adv = g.count > 1 ? c(C.dim, `  (${g.count} advisories)`) : "";
    console.log(`  ${c(sevColor(g.severity), sev)}  ${pkg}  ${fix}${adv}`);
    const dot = g.reachability === "imported" ? c(C.orange, "● reachable") : c(C.gray, `○ ${REACH_LABEL[g.reachability]}`);
    console.log(`        ${dot}`);
  }
  const reachable = groups.filter((g) => g.reachability === "imported").length;
  console.log("");
  console.log("  " + c(C.orange, "▸") + " " + c(C.bold, `${reachable} reachable`) + c(C.dim, ` · ${groups.length - reachable} without a direct import signal`));
  console.log("  " + c(C.dim, "Import signals prioritize review; they do not prove exploitability or safety.") + "\n");
}

main().catch((err) => {
  console.error(c(C.red, "PatchPilot CLI error: ") + (err instanceof Error ? err.message : String(err)));
  if (process.argv.includes("--json")) console.log(JSON.stringify({ error: "scan_failed", message: err instanceof Error ? err.message : String(err) }));
  process.exit(2);
});
