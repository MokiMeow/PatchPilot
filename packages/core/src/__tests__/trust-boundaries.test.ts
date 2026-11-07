import { mkdtempSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { collectFirstPartyImports, reachabilityForFinding } from "../reachability";
import { validateTelegramWebhookSecret } from "../telegram";

afterEach(() => vi.unstubAllEnvs());
describe("Telegram callback authentication", () => {
  it("fails closed when the shared webhook secret is missing", () => {
    vi.stubEnv("TELEGRAM_WEBHOOK_SECRET", "");
    expect(() => validateTelegramWebhookSecret("attacker-value")).toThrow(/Configure TELEGRAM_WEBHOOK_SECRET/);
  });
  it("compares full UTF-8 bytes and rejects a different secret", () => {
    vi.stubEnv("TELEGRAM_WEBHOOK_SECRET", "test-webhook-value");
    expect(() => validateTelegramWebhookSecret("test-webhook-value")).not.toThrow();
    expect(() => validateTelegramWebhookSecret("test-webhook-valuE")).toThrow(/invalid/);
    expect(() => validateTelegramWebhookSecret("different-length")).toThrow(/invalid/);
  });
});
describe("reachability coverage", () => {
  it.skipIf(process.platform === "win32")("does not read a symlink outside the project and marks coverage incomplete", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "patchpilot-imports-"));
    const external = mkdtempSync(path.join(os.tmpdir(), "patchpilot-external-"));
    try {
      writeFileSync(path.join(external, "outside.js"), 'import "example";');
      symlinkSync(path.join(external, "outside.js"), path.join(root, "linked.js"));
      const imports = collectFirstPartyImports(root);
      expect(imports.npm.has("example")).toBe(false);
      expect(imports.complete).toBe(false);
      expect(reachabilityForFinding({ packageName: "example", ecosystem: "npm", dependencyType: "direct" }, imports).status).toBe("unknown");
    } finally { rmSync(root, { recursive: true, force: true }); rmSync(external, { recursive: true, force: true }); }
  });
});
