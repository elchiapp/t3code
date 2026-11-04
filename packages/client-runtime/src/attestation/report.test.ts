import { describe, it, expect } from "vite-plus/test";
import type { AttestationStatus } from "@t3tools/contracts";
import { attestationReport } from "./report.ts";
const origin = "https://vm.example:8446";
const complete = (): AttestationStatus => ({
  origin,
  phase: "verified",
  message: "Verified",
  verifiedAt: 0,
  expiresAt: 60000,
  targets: {
    vmOrigin: origin,
    proxyOrigin: "https://vm.example:8447",
    inferenceProviderIds: ["tinfoil"],
  },
  checks: Object.fromEntries(
    [
      "hardware",
      "tls_key_commitment",
      "environment_connection",
      "inference",
      "proxy_workload",
      "key_custody",
      "inference_route",
    ].map((key) => [key, { state: "verified" }]),
  ),
});
describe("composer attestation colors", () => {
  it("uses gray for absent support, green for complete proof, yellow for partial proof, and red for failed available proof", () => {
    const full = complete();
    const partial = {
      ...full,
      checks: { ...full.checks, proxy_workload: { state: "not_configured" } },
    };
    const absent = {
      ...full,
      origin: "http://127.0.0.1:3773",
      phase: "unavailable" as const,
      checks: {
        environment_connection: { state: "verified" },
        inference: { state: "not_offered" },
      },
    };
    expect(
      attestationReport(full, true, "VM", { instanceId: "tinfoil", label: "Tinfoil" }).tone,
    ).toBe("green");
    expect(
      attestationReport(partial, true, "VM", { instanceId: "tinfoil", label: "Tinfoil" }).tone,
    ).toBe("yellow");
    expect(
      attestationReport(absent, false, "Mac", { instanceId: "codex", label: "Codex" }).tone,
    ).toBe("gray");
    for (const state of ["failed", "approval_required", "expired", "unavailable"]) {
      const failed = {
        ...full,
        phase: "failed" as const,
        checks: { ...full.checks, hardware: { state } },
      };
      expect(
        attestationReport(failed, false, "VM", { instanceId: "tinfoil", label: "Tinfoil" }).tone,
      ).toBe("red");
    }
    const update = {
      ...full,
      phase: "failed" as const,
      checks: { ...full.checks, inference: { state: "approval_required" } },
    };
    const report = attestationReport(update, false, "VM", {
      instanceId: "tinfoil",
      label: "Tinfoil",
    });
    expect(report.label).toBe("Tinfoil update needs approval");
    expect(report.actionLabel).toBe("Review update");
    expect(report.needsApproval).toBe(true);
    const remoteMac = attestationReport(
      {
        ...full,
        origin: "http://100.64.0.2:3773",
        checks: { ...full.checks, environment_connection: { state: "not_configured" } },
      },
      true,
      "Mac",
      { instanceId: "tinfoil", label: "Tinfoil" },
    );
    expect(remoteMac.tone).toBe("yellow");
    expect(remoteMac.sections[0]?.rows[0]?.result).toBe("Not configured");
    expect(remoteMac.sections[1]?.rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ title: "Proxy VM hardware", result: "Verified" }),
        expect.objectContaining({ title: "Proxy connection key", result: "Verified" }),
      ]),
    );
    const offline = { ...full, phase: "failed" as const, checks: {} };
    expect(
      attestationReport(offline, false, "VM", { instanceId: "tinfoil", label: "Tinfoil" }).tone,
    ).toBe("red");
  });
});
