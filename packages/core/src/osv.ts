import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import semver from "semver";
import { z } from "zod";
import { cvssBaseScore } from "./cvss";
import type { Vulnerability } from "./types";
import type { PackageManifest } from "./packageDetection";
import { getEnv } from "./env";
import { PatchPilotError } from "./errors";

export interface NormalizedOsvFinding {
  vulnerability: Vulnerability;
  packageName: string;
  ecosystem: string;
  currentVersion: string;
  fixedVersion?: string;
  affectedRanges: string[];
  dependencyType: "direct" | "transitive" | "unknown";
}

export interface OsvScanResult {
  findings: NormalizedOsvFinding[];
  scanner: "osv-scanner" | "osv-api";
  scanConfidence: "lockfile" | "direct_manifest_only";
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  references?: { url: string }[];
  database_specific?: { severity?: string };
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ type?: string; events?: Array<{ introduced?: string; fixed?: string; last_affected?: string; limit?: string }> }>;
    severity?: Array<{ type: string; score: string }>;
    versions?: string[];
    ecosystem_specific?: Record<string, unknown>;
  }>;
  severity?: Array<{ type: string; score: string }>;
}

function osvScannerBin(): string {
  return getEnv("PATCHPILOT_SCANNER_OSV_SCANNER_PATH") ?? "osv-scanner";
}

export function osvScannerAvailable(): boolean {
  if (getEnv("PATCHPILOT_DISABLE_OSV_SCANNER") === "true") return false;
  const bin = osvScannerBin();
  if (bin.includes("\\") || bin.includes("/")) return existsSync(bin);
  const result = spawnSync(process.platform === "win32" ? "where.exe" : "command", process.platform === "win32" ? [bin] : ["-v", bin], {
    encoding: "utf8",
    shell: process.platform !== "win32"
  });
  return result.status === 0;
}

const advisorySchema = z.object({ id: z.string().min(1) }).passthrough();
const batchSchema = z.object({ results: z.array(z.object({
  vulns: z.array(advisorySchema).optional(),
  next_page_token: z.string().optional()
}).passthrough().refine((result) => !("error" in result))) });
const REQUEST_TIMEOUT_MS = 15_000;

export async function queryOsvApi(manifest: PackageManifest): Promise<NormalizedOsvFinding[]> {
  const deps = { ...manifest.dependencies, ...manifest.devDependencies, ...manifest.optionalDependencies };
  const entries = Object.entries(deps).map(([name, rawVersion]) => {
    let version: string | undefined;
    try { version = manifest.ecosystem === "npm" ? semver.minVersion(rawVersion)?.version : rawVersion; } catch { /* unsupported specifier */ }
    if (!version) throw new PatchPilotError("osv_version_unresolved", `Cannot resolve ${name} from its manifest specifier; use OSV-Scanner with a lockfile.`, { packageName: name }, 422);
    return { name, version, seenPages: new Set<string>(), pageToken: undefined as string | undefined };
  });
  const findings = new Map<string, NormalizedOsvFinding>();
  const details = new Map<string, Promise<OsvVulnerability>>();
  for (let offset = 0; offset < entries.length; offset += 100) {
    let pending = entries.slice(offset, offset + 100);
    let pages = 0;
    while (pending.length > 0) {
      if (++pages > 100) throw new PatchPilotError("osv_pagination_failed", "OSV pagination exceeded its safety limit; scan incomplete.", {}, 502);
      const response = await fetch(getEnv("OSV_API_URL") ?? "https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        body: JSON.stringify({ queries: pending.map(({ name, version, pageToken }) => ({
          version, package: { name, ecosystem: manifest.ecosystem }, ...(pageToken ? { page_token: pageToken } : {})
        })) })
      });
      if (!response.ok) throw new PatchPilotError("osv_api_failed", `OSV API returned ${response.status}.`, { status: response.status }, 502);
      const body = batchSchema.safeParse(await response.json());
      if (!body.success || body.data.results.length !== pending.length) {
        throw new PatchPilotError("osv_response_invalid", "OSV returned a malformed or incomplete batch response; scan incomplete.", {}, 502);
      }
      const next: typeof pending = [];
      for (const [index, result] of body.data.results.entries()) {
        const entry = pending[index]!;
        for (const vuln of result.vulns ?? []) {
          if (!details.has(vuln.id)) details.set(vuln.id, fetchOsvVulnerability(vuln.id).catch(() => ({ id: vuln.id })));
          const hydrated = await details.get(vuln.id)!;
          const finding = normalizeOsvVulnerability(hydrated, entry.name, entry.version, "direct", manifest.ecosystem);
          findings.set(`${entry.name}\0${entry.version}\0${vuln.id}`, finding);
        }
        if (result.next_page_token) {
          if (entry.seenPages.has(result.next_page_token)) throw new PatchPilotError("osv_pagination_failed", "OSV repeated a page token; scan incomplete.", {}, 502);
          entry.seenPages.add(result.next_page_token);
          entry.pageToken = result.next_page_token;
          next.push(entry);
        }
      }
      pending = next;
    }
  }
  return [...findings.values()];
}

export async function queryOsvFindings(projectPath: string, manifests: PackageManifest[]): Promise<OsvScanResult> {
  const directNames = new Set(manifests.flatMap((manifest) => Object.keys({ ...manifest.dependencies, ...manifest.devDependencies, ...manifest.optionalDependencies })));
  const queryDirectManifests = async (): Promise<OsvScanResult> => {
    const apiFindings: NormalizedOsvFinding[] = [];
    for (const manifest of manifests) apiFindings.push(...await queryOsvApi(manifest));
    return { findings: apiFindings, scanner: "osv-api", scanConfidence: "direct_manifest_only" };
  };
  if (canRunOsvScanner(projectPath)) {
    const bin = osvScannerBin();
    const args = ["--format", "json", "--recursive", projectPath];
    const isCmd = process.platform === "win32" && /\.(cmd|bat)$/i.test(bin);
    const bare = !bin.includes("\\") && !bin.includes("/");
    const result = isCmd
      ? spawnSync(process.env.ComSpec ?? "cmd.exe", ["/d", "/c", bin, ...args], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 120_000 })
      : spawnSync(bin, args, { encoding: "utf8", shell: bare && process.platform === "win32", maxBuffer: 64 * 1024 * 1024, timeout: 120_000 });
    if (result.error || result.signal || (result.status !== 0 && result.status !== 1)) {
      if ((result.stderr ?? "").includes("No package sources found")) return await queryDirectManifests();
      throw new PatchPilotError("osv_scanner_failed", "OSV-Scanner failed before producing JSON output.", { stderr: result.stderr }, 502);
    }
    const findings = parseOsvScannerJson(result.stdout, directNames);
    if (result.status === 1 && findings.length === 0) throw new PatchPilotError("osv_response_invalid", "OSV-Scanner reported vulnerabilities but returned no findings; scan incomplete.", {}, 502);
    return { findings, scanner: "osv-scanner", scanConfidence: "lockfile" };
  }
  return await queryDirectManifests();
}

export function parseOsvScannerJson(raw: string, directNames: Set<string>): NormalizedOsvFinding[] {
  const validated = z.object({ results: z.array(z.object({ packages: z.array(z.object({
    package: z.object({ name: z.string().min(1), version: z.string().min(1), ecosystem: z.string().optional() }),
    vulnerabilities: z.array(advisorySchema).optional()
  }).passthrough()) }).passthrough().refine((result) => !("error" in result) && (result.errors === undefined || (Array.isArray(result.errors) && result.errors.length === 0)))) }).passthrough().refine((report) => !("error" in report) && (report.errors === undefined || (Array.isArray(report.errors) && report.errors.length === 0))).safeParse(JSON.parse(raw));
  if (!validated.success) throw new PatchPilotError("osv_response_invalid", "OSV-Scanner returned malformed or incomplete JSON; scan incomplete.", {}, 502);
  const parsed = validated.data as {
    results?: Array<{
      packages?: Array<{
        package?: { name?: string; version?: string; ecosystem?: string };
        vulnerabilities?: OsvVulnerability[];
      }>;
    }>;
  };
  return (parsed.results ?? []).flatMap((result) =>
    (result.packages ?? []).flatMap((pkg) => {
      const packageName = pkg.package?.name;
      const version = pkg.package?.version;
      if (!packageName || !version) return [];
      const dependencyType = directNames.has(packageName) ? "direct" : "transitive";
      const ecosystem = pkg.package?.ecosystem ?? "npm";
      return (pkg.vulnerabilities ?? []).map((vulnerability) => normalizeOsvVulnerability(vulnerability, packageName, version, dependencyType, ecosystem));
    })
  );
}

async function fetchOsvVulnerability(id: string): Promise<OsvVulnerability> {
  const base = (getEnv("OSV_API_URL") ?? "https://api.osv.dev/v1/querybatch").replace(/\/querybatch$/, "");
  const response = await fetch(`${base}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  if (!response.ok) throw new PatchPilotError("osv_vulnerability_fetch_failed", `OSV vulnerability detail returned ${response.status}.`, { id, status: response.status }, 502);
  const body = await response.json() as OsvVulnerability;
  if (!body || body.id !== id) throw new PatchPilotError("osv_response_invalid", "OSV returned a mismatched advisory.", { id }, 502);
  return body;
}

export function normalizeOsvVulnerability(
  vuln: OsvVulnerability,
  packageName: string,
  currentVersion: string,
  dependencyType: "direct" | "transitive" | "unknown",
  ecosystem = "npm"
): NormalizedOsvFinding {
  const cveIds = (vuln.aliases ?? []).filter((alias) => alias.startsWith("CVE-"));
  const ghsaIds = [vuln.id, ...(vuln.aliases ?? [])].filter((alias) => alias.startsWith("GHSA-"));
  const normalizeName = (name: string) => ecosystem.toLowerCase() === "pypi" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name;
  const affected = (vuln.affected ?? []).filter((item) => item.package?.name && normalizeName(item.package.name) === normalizeName(packageName) && item.package.ecosystem?.toLowerCase() === ecosystem.toLowerCase());
  const severity = parseSeverity(vuln, affected);
  return {
    vulnerability: {
      id: vuln.id,
      source: "osv",
      osvId: vuln.id,
      cveIds,
      ghsaIds,
      summary: vuln.summary ?? vuln.id,
      details: vuln.details,
      severity: severity.label,
      cvssScore: severity.cvssScore,
      publishedAt: vuln.published,
      modifiedAt: vuln.modified,
      references: (vuln.references ?? []).map((reference) => reference.url)
    },
    packageName,
    ecosystem,
    currentVersion,
    fixedVersion: selectFixedVersion(affected, currentVersion, ecosystem),
    affectedRanges: affected.flatMap((affected) =>
      (affected.ranges ?? []).flatMap((range) => (range.events ?? []).map((event) => JSON.stringify(event)))
    ),
    dependencyType
  };
}

type Affected = NonNullable<OsvVulnerability["affected"]>;

/** Never downgrade or borrow another package's fix; unsupported version schemes need manual review. */
function selectFixedVersion(affected: Affected, current: string, ecosystem: string): string | undefined {
  const compare = (a: string, b: string): number | undefined => {
    if (ecosystem.toLowerCase() === "npm") return semver.valid(a) && semver.valid(b) ? semver.compare(a, b) : undefined;
    // A safe subset of PEP 440. Pre/dev/post/local versions need a full ecosystem resolver.
    if (ecosystem.toLowerCase() !== "pypi" || !/^\d+(?:\.\d+)*$/.test(a) || !/^\d+(?:\.\d+)*$/.test(b)) return undefined;
    const aa = a.split(".").map(Number), bb = b.split(".").map(Number);
    for (let i = 0; i < Math.max(aa.length, bb.length); i++) { const diff = (aa[i] ?? 0) - (bb[i] ?? 0); if (diff) return diff; }
    return 0;
  };
  const ranges = affected.flatMap((item) => item.ranges ?? []).filter((range) => range.type === "SEMVER" || range.type === "ECOSYSTEM");
  // If any relevant interval is opaque, do not pretend a candidate clears it.
  if (ranges.some((range) => (range.events ?? []).some((event) => Object.values(event).some((bound) => bound !== "0" && compare(bound, current) === undefined)))) return undefined;
  const isAffected = (version: string): boolean => ranges.some((range) => {
    let active = false;
    for (const event of range.events ?? []) {
      if (event.introduced !== undefined && (event.introduced === "0" || (compare(version, event.introduced) ?? -1) >= 0)) active = true;
      if (event.fixed !== undefined && (compare(version, event.fixed) ?? -1) >= 0) active = false;
      if (event.last_affected !== undefined && (compare(version, event.last_affected) ?? -1) > 0) active = false;
      if (event.limit !== undefined && (compare(version, event.limit) ?? -1) >= 0) active = false;
    }
    return active;
  }) || affected.some((item) => item.versions?.some((affectedVersion) => compare(affectedVersion, version) === 0));
  if (!isAffected(current)) return undefined;
  const candidates = ranges.flatMap((range) => range.events ?? []).map((event) => event.fixed)
    .filter((version): version is string => Boolean(version) && (compare(version!, current) ?? -1) > 0)
    .filter((version) => !isAffected(version));
  return candidates.sort((a, b) => compare(a, b) ?? 0)[0];
}

function parseSeverity(vuln: OsvVulnerability, affected: Affected): { label: string; cvssScore?: number } {
  const scores = [...(vuln.severity ?? []), ...affected.flatMap((item) => item.severity ?? [])]
    .filter((item) => item.type.toUpperCase().startsWith("CVSS"))
    .map((item) => /^\d+(?:\.\d+)?$/.test(item.score) ? Number(item.score) : cvssBaseScore(item.score))
    .filter((score): score is number => score !== undefined && Number.isFinite(score) && score >= 0 && score <= 10);
  if (scores.length) { const score = Math.max(...scores); return { label: labelForCvss(score), cvssScore: score }; }
  const label = vuln.database_specific?.severity?.toLowerCase();
  if (label && ["critical", "high", "medium", "moderate", "low"].includes(label)) return { label: label === "moderate" ? "medium" : label };
  return { label: "unknown" };
}

function labelForCvss(score: number): string {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "unknown";
}

export function canRunOsvScanner(projectPath: string): boolean {
  return existsSync(projectPath) && osvScannerAvailable();
}
