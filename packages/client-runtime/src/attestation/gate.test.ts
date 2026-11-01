import { describe, expect, it } from "vite-plus/test";
import { ClientAttestationGate, unavailableAttestation } from "./gate.ts";
import type { AttestationStatus } from "@t3tools/contracts";

const origin = "https://host.example:8446";
const good = (expiresAt = 60_000): AttestationStatus => ({
  origin,
  phase: "verified",
  message: "Verified",
  verifiedAt: 0,
  expiresAt,
  checks: {
    environment_connection: { state: "verified" },
    hardware: { state: "verified" },
    tls_key_commitment: { state: "verified" },
    inference: { state: "verified" },
  },
});
const make = (verify: ConstructorParameters<typeof ClientAttestationGate>[0]) =>
  new ClientAttestationGate(
    verify,
    () => 0,
    () => 0,
  );

describe("client attestation gate", () => {
  it("keeps a current lease visible during background checking but waits before dispatch", async () => {
    let calls = 0;
    let finish: (status: AttestationStatus) => void = () => {};
    const gate = make(async () =>
      ++calls === 1
        ? good()
        : new Promise((resolve) => {
            finish = resolve;
          }),
    );
    await gate.authorize(origin);
    const delivery = gate.authorize(origin);
    await Promise.resolve();
    expect(gate.canSend(origin)).toBe(true);
    finish(unavailableAttestation(origin));
    await expect(delivery).rejects.toThrow("unavailable");
    expect(gate.canSend(origin)).toBe(false);
  });
  it("coalesces a send requested synchronously by a status subscriber", async () => {
    let calls = 0;
    const gate = make(async () => {
      calls++;
      return good();
    });
    let joined: Promise<void> | undefined;
    const unsubscribe = gate.subscribe(origin, () => {
      if (gate.get(origin).phase === "checking") joined = gate.authorize(origin);
    });
    try {
      await gate.authorize(origin);
      await joined;
      expect(calls).toBe(1);
    } finally {
      unsubscribe();
    }
  });
  it("blocks before verification and when the verifier is absent", async () => {
    const gate = make(async () => unavailableAttestation(origin));
    expect(gate.canSend(origin)).toBe(false);
    await expect(gate.authorize(origin)).rejects.toThrow("unavailable");
  });
  it("requires every proof rather than a verified flag", async () => {
    const gate = make(async () => ({ ...good(), checks: {} }));
    await expect(gate.authorize(origin)).rejects.toThrow("fresh device verification");
  });
  it("refuses evidence for a different environment", async () => {
    const gate = make(async () => ({ ...good(), origin: "https://other.example" }));
    await expect(gate.authorize(origin)).rejects.toThrow("another environment");
  });
  it("does not reuse one environment's permission for another", async () => {
    const gate = make(async () => good());
    await gate.authorize(origin);
    expect(gate.canSend(origin)).toBe(true);
    expect(gate.canSend("https://other.example")).toBe(false);
  });
  it("closes on expiry and refuses a failed renewal", async () => {
    let now = 0;
    const gate = new ClientAttestationGate(
      async () => (now === 0 ? good(1_000) : unavailableAttestation(origin)),
      () => now,
      () => now,
    );
    await gate.authorize(origin);
    now = 1_001;
    expect(gate.canSend(origin)).toBe(false);
    await expect(gate.authorize(origin)).rejects.toThrow("unavailable");
  });
  it("clock rollback cannot extend the monotonic lease", async () => {
    let wall = 0;
    let monotonic = 0;
    const gate = new ClientAttestationGate(
      async () => good(),
      () => wall,
      () => monotonic,
    );
    await gate.authorize(origin);
    wall = -10_000;
    monotonic = 60_001;
    expect(gate.canSend(origin)).toBe(false);
  });
  it("does not extend a short lease when the wall clock moves backwards", async () => {
    let wall = 0;
    let monotonic = 0;
    const gate = new ClientAttestationGate(
      async () => good(1_000),
      () => wall,
      () => monotonic,
    );
    await gate.authorize(origin);
    wall = -10_000;
    monotonic = 1_001;
    expect(gate.canSend(origin)).toBe(false);
  });
  it("rechecks the device verifier before every delivery, even with a cached lease", async () => {
    let healthy = true;
    const gate = make(async () => (healthy ? good() : unavailableAttestation(origin)));
    await gate.authorize(origin);
    healthy = false;
    await expect(gate.authorize(origin)).rejects.toThrow("unavailable");
    expect(gate.canSend(origin)).toBe(false);
  });
  it("shares one pending verification and permits no send before it resolves", async () => {
    let finish: (value: AttestationStatus) => void = () => {};
    let calls = 0;
    const gate = make(() => {
      calls++;
      return new Promise((resolve) => {
        finish = resolve;
      });
    });
    const a = gate.authorize(origin);
    const b = gate.authorize(origin);
    expect(gate.canSend(origin)).toBe(false);
    await Promise.resolve();
    finish(good());
    await Promise.all([a, b]);
    expect(calls).toBe(1);
    expect(gate.canSend(origin)).toBe(true);
  });
});
