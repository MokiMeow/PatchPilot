import { SEVERITY_RANK } from "./options";

export interface Group {
  package: string; ecosystem: string; currentVersion: string; severity: string;
  fixedVersion: string | null; reachability: string; count: number;
}

/** Groups per-advisory findings into one row per package. */
export function groupByPackage(findings: ReadonlyArray<Omit<Group, "count">>): Group[] {
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

