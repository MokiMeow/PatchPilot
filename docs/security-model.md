# Security Model

Secure defaults:

- No auto-merge.
- No production deploy.
- No fake safe states after scanner failure.
- No local scanning outside `PATCHPILOT_LOCAL_ROOTS`.
- No raw secret logging.
- No Telegram approval without HMAC and chat allowlist.
- No Telegram webhook callback accepted with a wrong `X-Telegram-Bot-Api-Secret-Token` and when no webhook secret is configured.
- No Codex execution when the CLI is missing, disabled, lacks sandbox flags, or exceeds timeout.
- No validation install lifecycle scripts unless `PATCHPILOT_ALLOW_VALIDATION_SCRIPTS=true`.

Controls implemented:

- Path realpath allowlist checks.
- Redaction for common token formats and high-entropy values.
- Signed approval callback tokens with expiration.
- Safe child process environment for validation commands.
- Safe npm validation install mode using `--ignore-scripts` by default.
- Validation artifacts such as `node_modules/`, build outputs, logs, and temporary workspace files are ignored, cleaned, and blocked from PR/patch commits.
- Secret-file denial before Codex workspace creation.
- Codex `--sandbox workspace-write`, ephemeral execution, and timeout enforcement.
- GitHub remote token scrubbing after clone/push.
- Workspace cleanup unless `PATCHPILOT_RETAIN_WORKSPACES=true`.
- Agent Supply-Chain Shield for `.env`, private keys, risky Codex config, MCP/package scripts, and risky GitHub Actions.
- Audit receipt hash chain.

Controls implemented/config-gated:

- Signed plugin registry with HMAC verification when `PATCHPILOT_PLUGIN_SIGNING_SECRET` is set.
- GitHub draft PR rollback by closing the PR and deleting the PatchPilot branch.
- Secret-manager file indirection through `PATCHPILOT_SECRETS_FILE`.

Controls planned:

- Docker/container worker isolation.
- Postgres row-level/multi-user controls.
- GitHub App scoped installation tokens.

## Deployment boundary

Run validation/remediation only on trusted repositories in an isolated worker.
A disposable directory and `--ignore-scripts` on installation do not sandbox
explicit repository test/build commands. The default JSON store is single-process
state, not a transactional multi-user database. Keep the service on loopback or
behind authenticated ingress; configure the dashboard token before remote access.
Do not use the hosted demo as a production approval service.

Workspace copying rejects symbolic links rather than reading targets outside the
approved source. Import collection skips symlinks and reports unknown reachability
when inspection is incomplete. A missing literal import is never a safety proof.
