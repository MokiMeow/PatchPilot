# @patchpilot/cli

A thin, standalone supply-chain scanner over `@patchpilot/core`. Scans a project
folder (npm + PyPI) against the real OSV database and tags each finding with the
**reachability (VEX-lite)** signal, so you fix what's actually imported first.

## Usage

```bash
# Published on npm, run from anywhere
npx patchpilot-cli scan ./my-app
npx patchpilot-cli scan . --fail-on high
npx patchpilot-cli scan . --json > findings.json

# From this monorepo
pnpm scan:cli /absolute/path/to/project
```

Options:

- `--json`: machine-readable output.
- `--fail-on <critical|high|medium|low>`: exit non-zero when a finding at or
  above that severity exists (for CI gating). Without this option, scan failures still exit non-zero.
- `NO_COLOR=1`: disable ANSI colors.

It queries the live OSV API / OSV-Scanner. Network failures are errors, not clean scans.

## Reachability tag

| Tag | Meaning |
|---|---|
| `reachable` | The vulnerable package is imported in your first-party source, fix first. |
| `import not observed` | No literal import observed. Scripts, dynamic loading and transitive use may still expose the dependency. |
| `transitive` | Pulled in by a parent dependency, not a first-party import. |
| `unknown` | Couldn't determine (e.g. PyPI install-name ≠ import-name). |

## Building a self-contained binary (for publishing)

The published `bin` is a single bundled file at `dist/index.js` (core is bundled
in, so the package has no runtime workspace dependency):

```bash
pnpm cli:bundle           # → apps/cli/dist/index.js (esbuild, ESM, node18+)
node apps/cli/dist/index.js scan ./my-app   # verify
```

## Publishing a new version

The published package (`patchpilot-cli` on npm) is a single bundled file with no
runtime dependencies (core is inlined). To cut a new version, bundle, then
publish a clean manifest (name `patchpilot-cli`, no workspace deps):

```bash
pnpm cli:bundle                  # → apps/cli/dist/index.js
# stage dist/ + README + LICENSE + a deps-free package.json, then:
npm publish --access public      # requires npm login as the package owner
```

## Trust and coverage

Exit codes: `0` means the scan finished without a known threshold violation;
`1` means a finding meets `--fail-on`; `2` means invalid arguments, an unsupported
project, a failed scan, or an unknown severity that prevents evaluating the gate.
A zero exit is not proof the project is vulnerability-free.

JSON output includes `scanConfidence`. `direct_manifest_only` uses version
estimates from root manifest constraints and does not inventory installed or
transitive dependencies. Install OSV-Scanner and provide lockfiles for accurate
resolved-version coverage. Malformed responses and unfinished pagination fail
closed. Advisory-detail outages preserve findings with unknown severity.

Fix versions are advisory targets, not guarantees of published availability or
application compatibility. The CLI never substitutes an older published version
when the advisory's fix is unavailable. Verify the target, regenerate the lockfile,
rescan, and run application tests before approving a patch.

When a package has multiple advisories with different fix targets, the grouped
report asks for manual review instead of assuming the largest target fixes every
advisory. Use `--json` to inspect each advisory separately. Unsupported Python
requirements (includes, URLs, unpinned names or compound ranges) produce an error
instead of silently disappearing from the scan.
