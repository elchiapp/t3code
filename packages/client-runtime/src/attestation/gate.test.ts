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
  it("does not require an unused proxy's update approval for a local provider without a TEE", async () => {
    const local = "http://127.0.0.1:3773";
    const gate = make(async () => ({
      ...good(),
      origin: local,
      phase: "failed",
      targets: {
        vmOrigin: origin,
        proxyOrigin: "https://host.example:8447",
        inferenceProviderIds: ["tinfoil"],
      },
      checks: { ...good().checks, hardware: { state: "approval_required" } },
    }));
    gate.setInferenceProvider(local, "thread-1", "codex");
    let reviews = 0;
    gate.onVersionReviewRequired(() => {
      reviews++;
    });
    let confirmations = 0;
    gate.setOverrideConfirmation(async () => {
      confirmations++;
      return true;
    });
    await gate.refresh(local);
    expect((await gate.authorizeWithOverride(local, "thread-1", "codex")).allowed).toBe(true);
    expect(reviews).toBe(0);
    expect(confirmations).toBe(0);
    expect(gate.hasOverride(local, "thread-1")).toBe(false);
    expect(gate.canProceed(local, "codex")).toBe(true);
  });
  it("allows missing inference coverage without consent but retains fresh VM checks", async () => {
    const targets = {
      vmOrigin: origin,
      proxyOrigin: "https://host.example:8447",
      inferenceProviderIds: ["tinfoil"],
    };
    let current: AttestationStatus = {
      ...good(),
      phase: "failed",
      targets,
      checks: { ...good().checks, inference: { state: "failed" } },
    };
    let confirmations = 0;
    let clock = 0;
    const gate = new ClientAttestationGate(
      async () => current,
      () => clock,
      () => clock,
    );
    gate.setOverrideConfirmation(async () => {
      confirmations++;
      return false;
    });
    await gate.refresh(origin);
    expect((await gate.authorizeWithOverride(origin, "thread-1", "codex")).allowed).toBe(true);
    expect(gate.canSend(origin, "codex")).toBe(false);
    expect(gate.canProceed(origin, "codex")).toBe(true);
    expect(confirmations).toBe(0);
    clock = 60_001;
    expect(gate.canProceed(origin, "codex")).toBe(false);
    clock = 0;
    current = { ...current, checks: { ...current.checks, hardware: { state: "failed" } } };
    await gate.refresh(origin);
    expect((await gate.authorizeWithOverride(origin, "thread-1", "codex")).allowed).toBe(false);
    expect(gate.canProceed(origin, "codex")).toBe(false);
  });

  it("does not treat an offline configured TEE as missing support", async () => {
    const targets = {
      vmOrigin: origin,
      proxyOrigin: "https://host.example:8447",
      inferenceProviderIds: ["tinfoil"],
    };
    const gate = make(async () => ({
      ...unavailableAttestation(origin),
      phase: "failed",
      targets,
    }));
    await gate.refresh(origin);
    expect(gate.get(origin, "tinfoil").checks.inference?.state).toBe("unavailable");
    expect(gate.canProceed(origin, "tinfoil")).toBe(false);
    expect((await gate.authorizeWithOverride(origin, "thread-1", "tinfoil")).allowed).toBe(false);
  });

  it("allows explicitly unconfigured environments without claiming verified attestation", async () => {
    const gate = make(async () => ({
      ...unavailableAttestation(origin),
      checks: {
        environment_connection: { state: "not_configured" },
        inference: { state: "not_configured" },
      },
    }));
    gate.setOverrideConfirmation(async () => {
      throw new Error("No confirmation expected");
    });
    await gate.refresh(origin);
    expect((await gate.authorizeWithOverride(origin, "thread-1")).allowed).toBe(true);
    expect(gate.canSend(origin)).toBe(false);
    expect(gate.hasOverride(origin, "thread-1")).toBe(false);
  });

  it("does not request consent for partial coverage without a failed available check", async () => {
    for (const missing of ["hardware", "inference", "proxy_workload"]) {
      const partial: AttestationStatus = {
        ...good(),
        phase: missing === "proxy_workload" ? "verified" : "unavailable",
        targets: {
          vmOrigin: origin,
          proxyOrigin: "https://host.example:8447",
          inferenceProviderIds: ["tinfoil"],
        },
        checks: { ...good().checks, [missing]: { state: "not_configured" } },
      };
      const gate = make(async () => partial);
      let confirmations = 0;
      gate.setOverrideConfirmation(async () => {
        confirmations++;
        return false;
      });
      expect((await gate.authorizeWithOverride(origin, "partial")).allowed, missing).toBe(true);
      expect(confirmations).toBe(0);
      expect(gate.hasOverride(origin, "partial")).toBe(false);
    }
  });
  it("waits for configured provider discovery rather than treating cold startup as absent support", async () => {
    const local = "http://127.0.0.1:3773";
    const proof = Promise.withResolvers<AttestationStatus>();
    const gate = make(() => proof.promise);
    const sending = gate.authorizeWithOverride(local, "cold", "tinfoil");
    expect(gate.canProceed(local, "tinfoil")).toBe(false);
    proof.resolve({
      ...good(),
      origin: local,
      phase: "failed",
      targets: {
        vmOrigin: origin,
        proxyOrigin: "https://host.example:8447",
        inferenceProviderIds: ["tinfoil"],
      },
      checks: { ...good().checks, hardware: { state: "approval_required" } },
    });
    expect((await sending).allowed).toBe(false);
  });

  it("does not allow conversation consent to authorize an unapproved TEE build", async () => {
    for (const component of ["hardware", "inference"] as const) {
      const changed: AttestationStatus = {
        ...good(),
        phase: "failed",
        message: "Exact-build approval required",
        targets: {
          vmOrigin: origin,
          proxyOrigin: "https://host.example:8447",
          inferenceProviderIds: ["tinfoil"],
        },
        checks: { ...good().checks, [component]: { state: "approval_required" } },
      };
      const gate = make(async () => changed);
      let confirmations = 0;
      const reviews: string[] = [];
      gate.onVersionReviewRequired((target) => reviews.push(target));
      gate.setOverrideConfirmation(async () => {
        confirmations++;
        return true;
      });
      gate.override(origin, "thread-1");
      await gate.refresh(origin);
      expect((await gate.authorizeWithOverride(origin, "thread-1")).allowed).toBe(false);
      expect(gate.hasOverride(origin, "thread-1")).toBe(false);
      expect(confirmations).toBe(0);
      expect(reviews).toEqual([origin]);
      if (component === "hardware")
        expect((await gate.authorizeWithOverride(origin, "thread-2", "codex")).allowed).toBe(false);
    }
  });

  it("checks protected TEE targets again before reusing old conversation consent", async () => {
    const targets = {
      vmOrigin: origin,
      proxyOrigin: "https://host.example:8447",
      inferenceProviderIds: ["tinfoil"],
    };
    let current: AttestationStatus = { ...good(), targets };
    const gate = make(async () => current);
    await gate.refresh(origin);
    gate.override(origin, "thread-1");
    current = {
      ...current,
      phase: "failed",
      checks: { ...current.checks, hardware: { state: "approval_required" } },
    };
    expect((await gate.authorizeWithOverride(origin, "thread-1")).allowed).toBe(false);
  });

  it("does not save plain consent if a new TEE build is detected while its dialog is open", async () => {
    let current = unavailableAttestation(origin);
    const gate = make(async () => current);
    const entered = Promise.withResolvers<void>();
    const decision = Promise.withResolvers<boolean>();
    gate.setOverrideConfirmation(async () => {
      entered.resolve();
      return decision.promise;
    });
    const authorization = gate.authorizeWithOverride(origin, "thread-1");
    await entered.promise;
    current = {
      ...good(),
      phase: "failed",
      checks: { ...good().checks, hardware: { state: "approval_required" } },
    };
    await gate.refresh(origin);
    decision.resolve(true);
    expect((await authorization).allowed).toBe(false);
    expect(gate.hasOverride(origin, "thread-1")).toBe(false);
  });

  it("moves draft consent to its conversation without authorizing the next draft", async () => {
    const gate = make(async () => unavailableAttestation(origin));
    gate.override(origin, "project-draft");
    gate.moveOverride(origin, "project-draft", "thread-1");
    expect(gate.hasOverride(origin, "thread-1")).toBe(true);
    expect(gate.hasOverride(origin, "project-draft")).toBe(false);
    expect((await gate.authorizeWithOverride(origin, "thread-2")).allowed).toBe(false);
  });

  it("honors Cancel even if verification recovers while the prompt is open", async () => {
    let healthy = false;
    const gate = make(async () => (healthy ? good() : unavailableAttestation(origin)));
    const entered = Promise.withResolvers<void>();
    const decision = Promise.withResolvers<boolean>();
    gate.setOverrideConfirmation(async () => {
      entered.resolve();
      return decision.promise;
    });
    const authorization = gate.authorizeWithOverride(origin, "thread-1");
    await entered.promise;
    healthy = true;
    await gate.refresh(origin);
    decision.resolve(false);
    expect((await authorization).allowed).toBe(false);
    expect(gate.canSend(origin)).toBe(true);
  });

  it("does not reuse an inference result for a different provider", async () => {
    const gate = make(async () => ({
      ...good(),
      checks: { ...good().checks, "inference:sealed-provider": { state: "verified" } },
    }));
    await gate.refresh(origin);
    expect(gate.canSend(origin, "sealed-provider")).toBe(true);
    expect(gate.canSend(origin, "public-provider")).toBe(false);
    expect(gate.get(origin, "public-provider").checks.inference?.state).toBe("not_configured");
    expect(gate.get(origin, "public-provider")).toBe(gate.get(origin, "public-provider"));
    expect(gate.get(origin, "codex").checks.inference?.state).toBe("not_offered");
    expect(gate.get(origin, "codex").message).toContain("not a verification failure");
    expect(gate.canSend(origin, "codex")).toBe(false);
  });

  it("an accepted override does not wait for an unavailable background verifier", async () => {
    const verification = Promise.withResolvers<AttestationStatus>();
    const gate = make(() => verification.promise);
    gate.override(origin, "thread-1");
    const authorization = await gate.authorizeWithOverride(origin, "thread-1");
    expect(authorization.allowed).toBe(true);
    expect(authorization.status.phase).not.toBe("verified");
    verification.resolve(unavailableAttestation(origin));
  });

  it("asks once per conversation and preserves the failed verification result", async () => {
    const gate = make(async () => unavailableAttestation(origin));
    const prompts: string[] = [];
    gate.setOverrideConfirmation(async (request) => {
      prompts.push(request.threadId);
      return true;
    });
    expect((await gate.authorizeWithOverride(origin, "thread-1")).allowed).toBe(true);
    expect((await gate.authorizeWithOverride(origin, "thread-1")).allowed).toBe(true);
    expect((await gate.authorizeWithOverride(origin, "thread-2")).allowed).toBe(true);
    expect(prompts).toEqual(["thread-1", "thread-2"]);
    expect(gate.get(origin).phase).toBe("unavailable");
    expect(gate.canSend(origin)).toBe(false);
  });

  it("cancellation and missing conversation context never authorize a transfer", async () => {
    const gate = make(async () => unavailableAttestation(origin));
    let prompts = 0;
    gate.setOverrideConfirmation(async () => {
      prompts++;
      return false;
    });
    expect((await gate.authorizeWithOverride(origin, "thread-1")).allowed).toBe(false);
    await expect(gate.authorize(origin)).rejects.toThrow("unavailable");
    expect(prompts).toBe(1);
    expect(gate.hasOverride(origin, "thread-1")).toBe(false);
  });

  it("coalesces confirmation for concurrent writes in one conversation", async () => {
    const gate = make(async () => unavailableAttestation(origin));
    const entered = Promise.withResolvers<void>();
    const decision = Promise.withResolvers<boolean>();
    let prompts = 0;
    gate.setOverrideConfirmation(async () => {
      prompts++;
      entered.resolve();
      return decision.promise;
    });
    const first = gate.authorizeWithOverride(origin, "thread-1");
    const second = gate.authorizeWithOverride(origin, "thread-1");
    await entered.promise;
    decision.resolve(true);
    expect((await first).allowed).toBe(true);
    expect((await second).allowed).toBe(true);
    expect(prompts).toBe(1);
  });

  it("verified connections never invoke the consent interface", async () => {
    const gate = make(async () => good());
    gate.setOverrideConfirmation(async () => {
      throw new Error("Verified connections must not prompt");
    });
    expect((await gate.authorizeWithOverride(origin, "thread-1")).allowed).toBe(true);
  });

  it("does not accept a receipt from a verifier replaced while it was running", async () => {
    let finish: (status: AttestationStatus) => void = () => {};
    const gate = make(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    const delivery = gate.authorize(origin);
    await Promise.resolve();
    gate.setDeviceVerifier(async () => unavailableAttestation(origin));
    finish(good());
    await expect(delivery).rejects.toThrow("Fresh verification");
    expect(gate.canSend(origin)).toBe(false);
  });
  it("closes an existing lease when the device verifier is removed", async () => {
    const gate = make(async () => good());
    await gate.authorize(origin);
    gate.setDeviceVerifier(async () => unavailableAttestation(origin));
    expect(gate.canSend(origin)).toBe(false);
    await expect(gate.authorize(origin)).rejects.toThrow("unavailable");
  });
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

  it("blocks legacy authorization before verification and when the verifier is absent", async () => {
    const gate = make(async () => unavailableAttestation(origin));
    expect(gate.canSend(origin)).toBe(false);
    await expect(gate.authorize(origin)).rejects.toThrow("unavailable");
  });

  it("returns an override request instead of throwing for a thread", async () => {
    const gate = make(async () => unavailableAttestation(origin));
    const authorization = await gate.authorizeWithOverride(origin, "thread-1");
    expect(authorization.allowed).toBe(false);
    expect(authorization.requiresOverride).toBe(true);
    expect(authorization.status.phase).toBe("unavailable");
  });

  it("requires every proof rather than a verified flag", async () => {
    const gate = make(async () => ({ ...good(), checks: {} }));
    await expect(gate.authorize(origin)).rejects.toThrow("fresh device verification");
    expect((await gate.authorizeWithOverride(origin, "thread-1")).requiresOverride).toBe(true);
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
    const firstDelivery = gate.authorize(origin);
    const secondDelivery = gate.authorize(origin);
    expect(gate.canSend(origin)).toBe(false);
    await Promise.resolve();
    finish(good());
    await Promise.all([firstDelivery, secondDelivery]);
    expect(calls).toBe(1);
    expect(gate.canSend(origin)).toBe(true);
  });

  it("remembers a send override per thread and asks again in a new thread", async () => {
    const gate = make(async () => unavailableAttestation(origin));
    const initial = await gate.authorizeWithOverride(origin, "thread-1");
    expect(initial.requiresOverride).toBe(true);

    gate.override(origin, "thread-1");
    const overridden = await gate.authorizeWithOverride(origin, "thread-1");
    expect(overridden.allowed).toBe(true);
    expect(overridden.requiresOverride).toBe(false);
    expect(overridden.status.phase).toBe("unavailable");

    const newThread = await gate.authorizeWithOverride(origin, "thread-2");
    expect(newThread.allowed).toBe(false);
    expect(newThread.requiresOverride).toBe(true);
  });

  it("never asks for an override when verification succeeded", async () => {
    const gate = make(async () => good());
    const authorization = await gate.authorizeWithOverride(origin, "thread-1");
    expect(authorization.allowed).toBe(true);
    expect(authorization.requiresOverride).toBe(false);
    expect(authorization.status.phase).toBe("verified");
  });
});
