import { describe, expect, it } from "vite-plus/test";
import { createCertificateVerifier, createDesktopVerifier } from "./desktopVerifier.ts";
import { ClientAttestationGate } from "@t3tools/client-runtime/attestation";

const origin = "https://vm.example:8446";
const key = "a".repeat(64);
const policy = {
  verifierOrigin: "http://127.0.0.1:3420",
  modelOrigin: "https://vm.example:8447",
  allowedEnvironmentOrigins: [origin, "http://127.0.0.1:3219"],
};
const proof = () => ({
  ready: true,
  modelOrigin: policy.modelOrigin,
  verifiedAt: 0,
  expiresAt: 60_000,
  tlsSpkiSha256: key,
  checks: {
    hardware: { state: "verified" },
    tls_key_commitment: { state: "verified" },
    inference: { state: "verified" },
  },
});
const services = () => ({
  readPolicy: async (): Promise<unknown> => policy,
  readStatus: async (): Promise<unknown> => proof(),
  refresh: async () => {},
  peerKey: async () => key,
  now: () => 0,
});

describe("desktop device verifier boundary", () => {
  it("checks the actual transport certificate even when a separate probe would pass", async () => {
    const verify = createCertificateVerifier(services());
    expect(await verify("vm.example", "b".repeat(64), true)).toBe(-2);
    expect(await verify("vm.example", key, true)).toBe(0);
  });
  it("keeps normal certificate validation for hosts without an attestation profile", async () => {
    const verify = createCertificateVerifier(services());
    expect(await verify("vm.example", key, false)).toBe(-2);
    expect(await verify("other.example", key, true)).toBe(-3);
    expect(await verify("other.example", key, false)).toBe(-2);
  });
  it("keeps the approved connection key enforced when fresh attestation is unavailable", async () => {
    const verify = createCertificateVerifier({
      ...services(),
      readPolicy: async () => ({ ...policy, tlsSpkiSha256: key }),
      readStatus: async () => {
        throw new Error("Proof service unavailable");
      },
    });
    expect(await verify("vm.example", key, true)).toBe(0);
    expect(await verify("vm.example", "b".repeat(64), true)).toBe(-2);
    expect(await verify("vm.example", key, false)).toBe(-2);
  });
  it("does not fall back to normal TLS when a configured pin is malformed", async () => {
    const verify = createCertificateVerifier({
      ...services(),
      readPolicy: async () => ({ ...policy, tlsSpkiSha256: "invalid" }),
    });
    expect(await verify("vm.example", key, true)).toBe(-2);
  });
  it("provides the complete native receipt required by the shared send gate", async () => {
    const gate = new ClientAttestationGate(
      createDesktopVerifier(services()),
      () => 0,
      () => 0,
    );
    await gate.authorize(origin);
    expect(gate.canSend(origin)).toBe(true);
  });
  it("accepts complete fresh local proof and the matching environment TLS key", async () => {
    const verify = createDesktopVerifier(services());
    expect((await verify({ origin })).phase).toBe("verified");
  });
  it("refuses a VM-provided verifier address", async () => {
    const verify = createDesktopVerifier({
      ...services(),
      readPolicy: async () => ({ ...policy, verifierOrigin: "https://vm.example" }),
    });
    expect((await verify({ origin })).phase).toBe("unavailable");
  });
  it("does not let an unlisted environment reuse a verified VM", async () => {
    let reads = 0;
    const verify = createDesktopVerifier({
      ...services(),
      readStatus: async () => {
        reads++;
        return proof();
      },
    });
    expect((await verify({ origin: "https://other.example" })).phase).toBe("unavailable");
    expect(reads).toBe(0);
  });
  it("rejects a ready boolean without the real checks", async () => {
    const verify = createDesktopVerifier({
      ...services(),
      readStatus: async () => ({ ...proof(), checks: {} }),
    });
    expect((await verify({ origin })).phase).toBe("failed");
  });
  it("rejects evidence for a different inference target", async () => {
    const verify = createDesktopVerifier({
      ...services(),
      readStatus: async () => ({ ...proof(), modelOrigin: "https://other.example" }),
    });
    const wrongTarget = await verify({ origin });
    expect(wrongTarget.phase).toBe("failed");
    expect(wrongTarget.checks.inference?.state).toBe("failed");
  });
  it("rejects the wrong environment TLS key", async () => {
    const verify = createDesktopVerifier({ ...services(), peerKey: async () => "b".repeat(64) });
    expect((await verify({ origin })).phase).toBe("failed");
  });
  it("rejects expired evidence when renewal fails", async () => {
    const verify = createDesktopVerifier({
      ...services(),
      readStatus: async () => ({ ...proof(), expiresAt: -1 }),
    });
    const expired = await verify({ origin });
    expect(expired.phase).toBe("failed");
    expect(expired.checks.hardware?.state).toBe("expired");
  });
  it("fails closed when the device verifier cannot be reached", async () => {
    const verify = createDesktopVerifier({
      ...services(),
      readStatus: async () => {
        throw new Error("offline");
      },
    });
    expect((await verify({ origin })).phase).toBe("failed");
  });
  it("permits an explicitly configured loopback T3 without a remote TLS probe", async () => {
    let probes = 0;
    const verify = createDesktopVerifier({
      ...services(),
      peerKey: async () => {
        probes++;
        return key;
      },
    });
    expect((await verify({ origin: "http://127.0.0.1:3219" })).phase).toBe("verified");
    expect(probes).toBe(0);
    const local = await verify({ origin: "http://127.0.0.1:3219" });
    expect(local.targets?.vmOrigin).toBe(origin);
    expect(local.targets?.proxyOrigin).toBe(policy.modelOrigin);
    expect(local.targets?.inferenceProviderIds).toEqual(["tinfoil"]);
  });
  it("missing policy never silently disables the gate", async () => {
    const verify = createDesktopVerifier({
      ...services(),
      readPolicy: async () => {
        throw new Error("missing");
      },
    });
    expect((await verify({ origin })).phase).toBe("unavailable");
  });
});
