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
    },
    verifyInference: async () => {
      calls.inference++;
      return { state: "verified", detail: "Fixture" };
    },
  };
  return { operations, calls };
}

describe("phone-side verification", () => {
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
        verifyHardware: async () => {
          throw new Error("signature invalid");
        },
      },
      () => 0,
    );
    expect((await verify({ origin })).phase).toBe("failed");
  });
  it("rejects an unapproved origin before requesting proof", async () => {
    const { operations, calls } = fixture();
    const verify = createMobileDeviceVerifier(operations, () => 0);
    expect((await verify({ origin: "https://attacker.example" })).phase).toBe("failed");
    expect(calls.collection).toBe(0);
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
        verifyInference: async () => ({
          state: "approval_required",
          detail: "Release approval is required.",
        }),
      },
      () => 0,
    );
    expect((await verify({ origin })).phase).toBe("failed");
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
