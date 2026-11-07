# Security and reliability review, 7 November 2026

## Research and decisions

PatchPilot is a security decision tool, so a failed scan must never become a
clean result, and a suggested fix must belong to the affected package/version.
This review prioritizes those boundaries over adding more integrations.

- [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/) guarantees
  response ordering and requires per-query pagination. Batch result cardinality
  and structure are now checked; paginated queries continue independently, with
  repeat-token/iteration bounds and network deadlines.
- [OSV schema](https://ossf.github.io/osv-schema/) associates ranges and severity
  with specific packages. Fix selection now matches package and ecosystem,
  rejects downgrades, excludes Git ranges, and checks overlapping intervals.
  Only npm SemVer and numeric PyPI releases are resolved automatically. Opaque
  release schemes need manual review. A fix is not proof of registry availability.
- [Python version ordering](https://packaging.python.org/en/latest/specifications/version-specifiers/)
  treats trailing zero components as equivalent and orders components as integers.
  Numeric comparisons use arbitrary precision. Unsupported interval boundaries or
  explicit affected-version spellings suppress the automatic fix, not the finding.
  The requirements parser rejects unsupported entries and duplicate
  [canonical package names](https://packaging.python.org/en/latest/specifications/name-normalization/)
  rather than overwriting conditional versions. It is not a full
  [pip requirements resolver](https://pip.pypa.io/en/stable/reference/requirements-file-format/).
- [FIRST CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document)
  specifies vector scoring and integer-safe rounding. CVSS 3.0/3.1 base vectors
  now produce actual scores rather than unknown severity. CVSS v2/v4 vector
  calculation is not implemented; database severity labels are used when present,
  otherwise severity stays unknown. CLI severity gates reject unknown severity.
- [Gitleaks](https://github.com/gitleaks/gitleaks/blob/master/README.md),
  [Semgrep](https://docs.semgrep.dev/cli-reference), and
  [Trivy](https://trivy.dev/docs/dev/guide/configuration/others/) have different
  exit-code semantics. Gitleaks finding exit code is set explicitly; operational
  errors, malformed reports and partial analysis are not completed scans.
- [Telegram webhook authentication](https://core.telegram.org/bots/api#setwebhook)
  uses a shared secret header. All callback requests now require configuration
  and a matching secret, including short unsigned callback IDs. Chat allowlisting
  is not a substitute for authenticating the HTTP request.
- [Next.js 15.5.29](https://github.com/vercel/next.js/releases/tag/v15.5.29)
  includes the November security fixes. Next stays on its existing maintenance
  line to avoid a framework-major migration. Updated compatible dependencies,
  upgraded simple-git to 4.0.2 for its command-safety fixes, and Vitest to 4.1.12.
  The lockfile is authoritative. PostCSS and the unused PptxGenJS image-size
  dependency have explicit patched overrides.

## Product and architecture changes

The CLI validates policy flags before scanning, distinguishes policy violations
from execution errors, includes scan coverage in JSON, and no longer replaces an
unavailable fix with an older potentially vulnerable registry version. CLI and
Findings page language no longer calls an absent import “likely unused.”
Pagination now exposes the current page and result range to assistive technology.
Grouped CLI fixes require identical per-advisory targets. Divergent targets or an
advisory without a known target require manual review: the largest version can
reintroduce another vulnerability. JSON findings remain per-advisory.
LLM remediation plans must use the exact advisory target. URLs, aliases and ranges
are not coerced into versions, and later releases need a fresh vulnerability check.

Remediation workspace copies reject symlinks; import inspection skips them and
marks incomplete inspection unknown. This prevents following a project link to
unrelated files or traversing a symlink cycle. It is not a host sandbox or a
complete defense against a concurrently malicious filesystem writer.

CI uses pinned action commits, read-only permissions, frozen dependencies with
install scripts disabled, type/lint checks, regression tests, production build,
CLI bundle checks, and a high/critical dependency audit gate.

The November 7 dependency audit moved from 97 advisory entries (9 critical) to
zero known advisories in the resolved tree. This is a point-in-time registry
result, not a guarantee against future vulnerabilities.

## Verification and remaining limits

Regression tests cover malformed/partial scanner output, advisory pagination,
package-specific fix selection, CVSS vectors, CLI policy parsing, symlink escapes,
and missing webhook authentication. Tests use controlled local fixtures rather
than sending approvals or calling paid model providers.

The repository still uses a single-process JSON state store and optional
best-effort Postgres mirroring. Atomic transactional writes, multi-process
coordination, schema migration and durable job/approval idempotency deserve a
separate architecture change. Middleware token authentication is not a multi-user
identity system. Remote deployments need authenticated ingress and CSRF/session
hardening. Do not expose an unconfigured dashboard publicly.

Explicit repository test/build scripts execute on the worker host. Disposable
workspaces and scrubbed environment variables are hygiene, not sandbox isolation.
Use trusted repositories and isolated workers until stronger process/container
isolation is implemented. Live GitHub mutations, Telegram delivery, model calls,
Redis/Postgres services and deployment remain credential-gated and are not
validated by unit tests or the build.

Remediation still targets one advisory at a time. Its install/test/build checks
are not a fresh vulnerability scan of the entire resolved dependency graph.
Before approving a generated patch, rescan the resulting lockfile and review all
remaining advisories; a per-advisory target is not a package-wide safety guarantee.
