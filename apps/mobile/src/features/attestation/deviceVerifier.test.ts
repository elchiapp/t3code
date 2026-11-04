import { describe, expect, it } from "vite-plus/test";
import { createMobileDeviceVerifier, type MobileProofOperations } from "./deviceVerifier";

const origin = "https://vm.example:8446";
function fixture() {
  const calls = { hardware: 0, inference: 0, collection: 0 };
  const operations: MobileProofOperations = {
    policy: {
      environmentOrigins: [origin],
      proofOrigin: "http://100.64.0.1:3430",
      modelOrigin: "https://vm.example:8447",
      tlsSpkiSha256: "a".repeat(64),
    },
    transportProtected: async () => true,
    prepare: async () => ({
      nonce: "challenge",
      challenge: { nonce: "committed" },
      expiresAt: 60_000,
    }),
    collect: async () => {
      calls.collection++;
      return { fake: true };
    },
    verifyHardware: async () => {
      calls.hardware++;
      return { state: "verified" };
    },
    verifyInference: async () => {
      calls.inference++;
      return { state: "verified", detail: "Fixture" };
    },
  };
  return { operations, calls };
}

describe("phone-side verification", () => {
  it("reports a valid changed firmware as approval required without treating the matching connection key as broken", async () => {
    const { operations } = fixture();
    const verify = createMobileDeviceVerifier(
      {
        ...operations,
        verifyHardware: async () => ({
          state: "approval_required",
          detail: "Review the exact build",
        }),
      },
      () => 0,
    );
    const result = await verify({ origin });
    expect(result.phase).not.toBe("verified");
    expect(result.checks.hardware?.state).toBe("approval_required");
    expect(result.checks.tls_key_commitment?.state).toBe("verified");
    expect(result.message).toContain("system authentication");
  });
  it("verifies hardware and inference locally without a laptop service", async () => {
    const { operations, calls } = fixture();
    const verify = createMobileDeviceVerifier(operations, () => 0);
    const result = await verify({ origin });
    expect(result.phase).toBe("verified");
    expect(calls).toEqual({ hardware: 1, inference: 1, collection: 1 });
    expect(result.checks.proxy_workload?.state).toBe("not_configured");
  });
  it("never accepts server-supplied success without cryptographic verification", async () => {
    const { operations } = fixture();
    const verify = createMobileDeviceVerifier(
      {
        ...operations,
        policy: { ...operations.policy, inferenceOrigin: "https://inference.example" },
        verifyHardware: async () => {
          throw new Error("signature invalid");
        },
      },
      () => 0,
    );
    const result = await verify({ origin });
    expect(result.phase).toBe("failed");
    expect(result.checks.hardware?.state).toBe("failed");
    expect(result.checks.inference?.state).toBe("verified");
    const remoteMac = await verify({ origin: "http://100.84.28.120:3773" });
    expect(remoteMac.phase).toBe("failed");
    expect(remoteMac.checks.hardware?.state).toBe("failed");
    expect(remoteMac.checks.environment_connection?.state).toBe("not_configured");
  });
  it("reports an unconfigured environment without reusing the VM proof", async () => {
    const { operations, calls } = fixture();
    const verify = createMobileDeviceVerifier(operations, () => 0);
    const result = await verify({ origin: "https://other.example" });
    expect(result.phase).toBe("unavailable");
    expect(result.checks.environment_connection?.state).toBe("not_configured");
    expect(calls.collection).toBe(0);
    const proxyFixture = fixture();
    const proxyVerifier = createMobileDeviceVerifier(
      {
        ...proxyFixture.operations,
        policy: {
          ...proxyFixture.operations.policy,
          inferenceOrigin: "https://inference.example",
          inferenceProviderIds: ["tinfoil"],
        },
      },
      () => 0,
    );
    const remoteMac = "http://100.84.28.120:3773";
    const proxyResult = await proxyVerifier({ origin: remoteMac });
    expect(proxyResult.checks.environment_connection?.state).toBe("not_configured");
    expect(proxyResult.checks.hardware?.state).toBe("verified");
    expect(proxyResult.checks.tls_key_commitment?.state).toBe("verified");
    expect(proxyResult.checks["inference:tinfoil"]?.state).toBe("verified");
    expect(proxyResult.targets?.vmOrigin).toBe(origin);
    expect(proxyResult.origin).toBe(remoteMac);
    expect(proxyFixture.calls).toEqual({ hardware: 1, inference: 1, collection: 1 });
  });
  it("requires actual native transport protection even with a cached receipt", async () => {
    const { operations } = fixture();
    let protectedConnection = true;
    const verify = createMobileDeviceVerifier(
      { ...operations, transportProtected: async () => protectedConnection },
      () => 0,
    );
    expect((await verify({ origin })).phase).toBe("verified");
    protectedConnection = false;
    expect((await verify({ origin })).phase).toBe("failed");
  });
  it("does not allow an unapproved inference release", async () => {
    const { operations } = fixture();
    const verify = createMobileDeviceVerifier(
      {
        ...operations,
        policy: { ...operations.policy, inferenceOrigin: "https://inference.example" },
        verifyInference: async () => ({
          state: "approval_required",
          detail: "Release approval is required.",
        }),
      },
      () => 0,
    );
    const result = await verify({ origin });
    expect(result.phase).toBe("failed");
    expect(result.checks.hardware?.state).toBe("verified");
    expect(result.checks.inference?.state).toBe("approval_required");
    const remoteMac = await verify({ origin: "http://100.84.28.120:3773" });
    expect(remoteMac.phase).toBe("failed");
    expect(remoteMac.checks.inference?.state).toBe("approval_required");
    expect(remoteMac.targets?.vmOrigin).toBe(origin);
  });
  it("refuses proof which expires while verification runs", async () => {
    const { operations } = fixture();
    let now = 0;
    const verify = createMobileDeviceVerifier(
      {
        ...operations,
        verifyInference: async () => {
          now = 60_001;
          return { state: "verified", detail: "Fixture" };
        },
      },
      () => now,
    );
    expect((await verify({ origin })).phase).toBe("failed");
  });
});
