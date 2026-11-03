import { expect, it } from "vite-plus/test";
import type { AttestationVersionReview } from "@t3tools/contracts";
import { createDeviceApprovalController, type DeviceVersionDecisionRecord } from "./approvals.ts";

function setup() {
  let current: AttestationVersionReview = {
    id: "native-review",
    origin: "https://vm.example:8446",
    component: "vm-firmware",
    targetOrigin: "https://vm.example:8447",
    binding: "c".repeat(64),
    vendor: "Google",
    title: "VM boot firmware",
    version: "200",
    fingerprint: "b".repeat(96),
    previousVersion: "100",
    previousFingerprint: "a".repeat(96),
    eligible: true,
    approvalState: "required",
    explanation: "Test-only verified facts from an injected device verifier.",
    changes: [],
    links: [],
    sourceAvailability: "No public source mapping.",
    expiresAt: 61_000,
  };
  let values: ReadonlyArray<DeviceVersionDecisionRecord> = [];
  let authenticate = async () => true;
  let beforeRead = async () => {};
  let id = 0;
  const controller = createDeviceApprovalController(
    {
      review: async () => [current],
      authenticate: () => authenticate(),
      read: async () => {
        await beforeRead();
        return values;
      },
      write: async (next) => {
        values = next;
      },
      invalidate: () => {},
    },
    () => 1_000,
    () => `review-${++id}`,
  );
  return {
    controller,
    origin: current.origin,
    values: () => values,
    current: () => current,
    replace: (next: AttestationVersionReview) => {
      current = next;
    },
    authenticate: (next: () => Promise<boolean>) => {
      authenticate = next;
    },
    beforeRead: (next: () => Promise<void>) => {
      beforeRead = next;
    },
  };
}

it("requires device authentication and fresh matching evidence before saving the exact identity", async () => {
  const test = setup();
  const [review] = await test.controller.review(test.origin);
  await expect(test.controller.decide(review!.id, "approve")).resolves.toBe("approved");
  expect(test.values()).toEqual([
    {
      component: "vm-firmware",
      targetOrigin: "https://vm.example:8447",
      binding: "c".repeat(64),
      version: "200",
      fingerprint: "b".repeat(96),
      action: "approve",
      decidedAt: 1_000,
    },
  ]);
  await expect(test.controller.decide(review!.id, "approve")).rejects.toThrow(
    "Review this exact version again",
  );
});

it("keeps approval absent when the native authentication dialog is cancelled", async () => {
  const test = setup();
  test.authenticate(async () => false);
  const [review] = await test.controller.review(test.origin);
  await expect(test.controller.decide(review!.id, "approve")).resolves.toBe("cancelled");
  expect(test.values()).toEqual([]);
  await expect(test.controller.decide(review!.id, "approve")).rejects.toThrow(
    "Review this exact version again",
  );
});

it("does not save approval if its review was closed while authentication was open", async () => {
  const test = setup();
  let unlock!: (value: boolean) => void;
  let shown!: () => void;
  const opened = new Promise<void>((resolve) => {
    shown = resolve;
  });
  test.authenticate(
    () =>
      new Promise<boolean>((resolve) => {
        unlock = resolve;
        shown();
      }),
  );
  const [review] = await test.controller.review(test.origin);
  const decision = test.controller.decide(review!.id, "approve");
  await opened;
  await test.controller.decide(review!.id, "cancel");
  unlock(true);
  await expect(decision).resolves.toBe("cancelled");
  expect(test.values()).toEqual([]);
});

it("rejects a different build, connection key or baseline after authentication", async () => {
  for (const change of [
    { fingerprint: "d".repeat(96) },
    { binding: "e".repeat(64) },
    { previousFingerprint: "f".repeat(96) },
    { approvalState: "revoked" as const },
    { eligible: false },
  ]) {
    const test = setup();
    test.authenticate(async () => {
      test.replace({ ...test.current(), ...change });
      return true;
    });
    const [review] = await test.controller.review(test.origin);
    await expect(test.controller.decide(review!.id, "approve")).rejects.toThrow(
      "version or its evidence changed",
    );
    expect(test.values()).toEqual([]);
  }
});

it("does not save approval if the review closes while the protected store is read", async () => {
  const test = setup();
  let release!: () => void;
  let entered!: () => void;
  const reading = new Promise<void>((resolve) => {
    entered = resolve;
  });
  test.beforeRead(
    () =>
      new Promise<void>((resolve) => {
        release = resolve;
        entered();
      }),
  );
  const [review] = await test.controller.review(test.origin);
  const decision = test.controller.decide(review!.id, "approve");
  await reading;
  await test.controller.decide(review!.id, "cancel");
  release();
  await expect(decision).resolves.toBe("cancelled");
  expect(test.values()).toEqual([]);
});

it("refuses unverified candidates and caller-invented review IDs", async () => {
  const test = setup();
  test.replace({ ...test.current(), eligible: false });
  const [review] = await test.controller.review(test.origin);
  await expect(test.controller.decide(review!.id, "approve")).rejects.toThrow(
    "required evidence checks",
  );
  await expect(test.controller.decide("invented", "approve")).rejects.toThrow(
    "Review this exact version again",
  );
  expect(test.values()).toEqual([]);
});

it("does not revoke a newer approval using a stale review of the older version", async () => {
  const test = setup();
  const [older] = await test.controller.review(test.origin);
  test.replace({ ...test.current(), version: "300", fingerprint: "d".repeat(96) });
  const [newer] = await test.controller.review(test.origin);
  await test.controller.decide(newer!.id, "approve");
  await expect(test.controller.decide(older!.id, "revoke")).rejects.toThrow(
    "saved approval changed",
  );
  expect(test.values()[0]?.fingerprint).toBe("d".repeat(96));
});

it("rejects review facts for another environment or an expired review", async () => {
  const test = setup();
  await expect(test.controller.review("https://other.example")).rejects.toThrow(
    "does not match this environment",
  );
  test.replace({ ...test.current(), expiresAt: 999 });
  await expect(test.controller.review(test.origin)).rejects.toThrow("has expired");
  expect(test.values()).toEqual([]);
});

it("records an explicit revocation so a signed-in baseline is not silently trusted again", async () => {
  const test = setup();
  const [review] = await test.controller.review(test.origin);
  await test.controller.decide(review!.id, "revoke");
  expect(test.values()).toEqual([
    {
      component: "vm-firmware",
      targetOrigin: "https://vm.example:8447",
      binding: "c".repeat(64),
      version: "200",
      fingerprint: "b".repeat(96),
      action: "revoke",
      decidedAt: 1_000,
    },
  ]);
});
