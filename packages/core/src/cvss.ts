/** CVSS v3.0/v3.1 base scoring, per FIRST's equations (not temporal/environmental scoring).
 * Unsupported or malformed vectors stay unknown; never guess a severity.
 * https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
 */
export function cvssBaseScore(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined;
  const metrics: Record<string, string> = {};
  for (const part of vector.split("/").slice(1)) {
    const pair = part.split(":");
    if (pair.length !== 2 || !pair[0] || !pair[1] || metrics[pair[0]]) return undefined;
    metrics[pair[0]] = pair[1];
  }
  const weight = (key: string, values: Record<string, number>) => values[metrics[key] ?? ""];
  const changed = metrics.S === "C";
  if (!changed && metrics.S !== "U") return undefined;
  const av = weight("AV", { N: .85, A: .62, L: .55, P: .2 });
  const ac = weight("AC", { L: .77, H: .44 });
  const pr = weight("PR", changed ? { N: .85, L: .68, H: .5 } : { N: .85, L: .62, H: .27 });
  const ui = weight("UI", { N: .85, R: .62 });
  const c = weight("C", { N: 0, L: .22, H: .56 });
  const i = weight("I", { N: 0, L: .22, H: .56 });
  const a = weight("A", { N: 0, L: .22, H: .56 });
  if (av === undefined || ac === undefined || pr === undefined || ui === undefined || c === undefined || i === undefined || a === undefined) return undefined;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const raw = Math.min((impact + 8.22 * av * ac * pr * ui) * (changed ? 1.08 : 1), 10);
  // FIRST Appendix A integer rounding avoids floating-point boundary drift.
  const scaled = Math.round(raw * 100_000);
  return scaled % 10_000 === 0 ? scaled / 100_000 : (Math.floor(scaled / 10_000) + 1) / 10;
}
