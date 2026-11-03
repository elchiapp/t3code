import type { AttestationVersionReview, DeviceVersionDecisionRecord } from "@t3tools/contracts";
export type { DeviceVersionDecisionRecord } from "@t3tools/contracts";

export interface DeviceApprovalOperations {
  readonly review: (origin: string) => Promise<ReadonlyArray<AttestationVersionReview>>;
  readonly authenticate: (reason: string, review: AttestationVersionReview) => Promise<boolean>;
  readonly read: () => Promise<ReadonlyArray<DeviceVersionDecisionRecord>>;
  readonly write: (values: ReadonlyArray<DeviceVersionDecisionRecord>) => Promise<void>;
  readonly invalidate: () => void;
}

const scope = (
  value: Pick<DeviceVersionDecisionRecord, "component" | "targetOrigin" | "binding">,
) => JSON.stringify([value.component, value.targetOrigin, value.binding]);

const identity = (value: AttestationVersionReview) =>
  JSON.stringify([
    scope(value),
    value.version,
    value.fingerprint,
    value.previousFingerprint,
    value.approvalState,
  ]);

/** Review facts come from the device verifier; a renderer can submit only its one-use review ID. */
export function createDeviceApprovalController(
  operations: DeviceApprovalOperations,
  now: () => number,
  newId: () => string | Promise<string>,
) {
  const pending = new Map<string, AttestationVersionReview>();
  const active = new Map<string, { cancelled: boolean }>();
  let decisions = Promise.resolve();
  return {
    async review(origin: string): Promise<ReadonlyArray<AttestationVersionReview>> {
      const reviews = await operations.review(origin);
      const issued: AttestationVersionReview[] = [];
      for (const value of reviews) {
        if (value.origin !== origin || value.expiresAt <= now())
          throw new Error("The review does not match this environment or has expired.");
        const review = { ...value, id: await newId() };
        while (pending.size >= 16) pending.delete(pending.keys().next().value!);
        pending.set(review.id, review);
        issued.push(review);
      }
      return issued;
    },
    decide(
      reviewId: string,
      action: "approve" | "revoke" | "cancel",
    ): Promise<"approved" | "revoked" | "cancelled"> {
      if (action === "cancel") {
        pending.delete(reviewId);
        const decision = active.get(reviewId);
        if (decision) decision.cancelled = true;
        return Promise.resolve("cancelled");
      }
      const result = decisions.then(async () => {
        const selected = pending.get(reviewId);
        pending.delete(reviewId);
        if (!selected || selected.expiresAt <= now())
          throw new Error("Review this exact version again before changing approval.");
        if (action === "approve" && !selected.eligible)
          throw new Error("This version has not passed the required evidence checks.");
        const decision = { cancelled: false };
        active.set(reviewId, decision);
        try {
          if (action === "approve") {
            const authenticated = await operations.authenticate(
              `Approve ${selected.vendor} ${selected.version} (${selected.fingerprint.slice(0, 12)})`,
              selected,
            );
            if (!authenticated || decision.cancelled) return "cancelled" as const;
            const fresh = (await operations.review(selected.origin)).find(
              (value) => identity(value) === identity(selected),
            );
            if (!fresh?.eligible || fresh.expiresAt <= now())
              throw new Error("The version or its evidence changed. Review it again.");
          }
          if (decision.cancelled) return "cancelled" as const;
          const stored = await operations.read();
          if (decision.cancelled) return "cancelled" as const;
          const existing = stored.find((value) => scope(value) === scope(selected));
          if (action === "revoke" && existing && existing.fingerprint !== selected.fingerprint)
            throw new Error("The saved approval changed. Review it again.");
          const values = stored.filter((value) => scope(value) !== scope(selected));
          if (values.length >= 32) throw new Error("Too many saved version approvals.");
          values.push({
            component: selected.component,
            targetOrigin: selected.targetOrigin,
            binding: selected.binding,
            version: selected.version,
            fingerprint: selected.fingerprint,
            action,
            decidedAt: now(),
          });
          operations.invalidate();
          try {
            await operations.write(values);
          } finally {
            operations.invalidate();
          }
          return action === "approve" ? ("approved" as const) : ("revoked" as const);
        } finally {
          active.delete(reviewId);
        }
      });
      decisions = result.then(
        () => undefined,
        () => undefined,
      );
      return result;
    },
  };
}
