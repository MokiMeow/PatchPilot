export const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

/** Parse flags before touching the filesystem or network. Typos must not disable CI gates. */
export function parseScanOptions(args: string[]): { target?: string; json: boolean; failOn?: string } {
  const options: { target?: string; json: boolean; failOn?: string } = { json: false };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--json") options.json = true;
    else if (arg === "--fail-on") {
      const level = args[++i]?.toLowerCase();
      if (!level || !(Object.hasOwn(SEVERITY_RANK, level)) || options.failOn) throw new Error("--fail-on requires one of: critical, high, medium, low (once).");
      options.failOn = level;
    } else if (arg.startsWith("-")) throw new Error(`Unknown option: ${arg}`);
    else if (options.target !== undefined) throw new Error("Only one project path may be scanned at a time.");
    else options.target = arg;
  }
  return options;
}

/** 1 = known policy violation; 2 = cannot establish the requested severity gate. */
export function severityExitCode(severities: string[], threshold?: string): 0 | 1 | 2 {
  if (!threshold) return 0;
  if (!(Object.hasOwn(SEVERITY_RANK, threshold))) return 2;
  if (severities.some((severity) => (SEVERITY_RANK[severity] ?? 0) >= SEVERITY_RANK[threshold]!)) return 1;
  return severities.some((severity) => !(Object.hasOwn(SEVERITY_RANK, severity))) ? 2 : 0;
}
