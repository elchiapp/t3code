import type {
  AttestationVersionReview,
  AttestationVersionDecision,
  DesktopBridge,
} from "@t3tools/contracts";

export interface DeviceVersionOperations {
  readonly review: (origin: string) => Promise<ReadonlyArray<AttestationVersionReview>>;
  readonly decide: (
    decision: AttestationVersionDecision,
  ) => Promise<"approved" | "revoked" | "cancelled">;
}

let registered: DeviceVersionOperations | undefined;
const pending = new Map<string, DeviceVersionOperations>();

function desktopBridge(): DesktopBridge | undefined {
  return (globalThis as { window?: { desktopBridge?: DesktopBridge } }).window?.desktopBridge;
}

function operations(): DeviceVersionOperations | undefined {
  if (registered) return registered;
  const bridge = desktopBridge();
  if (!bridge?.getAttestationVersionReviews || !bridge.decideAttestationVersion) return undefined;
  return {
    review: (origin) => bridge.getAttestationVersionReviews!({ origin, refresh: true }),
    decide: (decision) => bridge.decideAttestationVersion!(decision),
  };
}

export function registerDeviceVersionOperations(next: DeviceVersionOperations): () => void {
  if (registered && registered !== next) {
    for (const [reviewId, owner] of pending) {
      if (owner !== registered) continue;
      pending.delete(reviewId);
      void owner.decide({ reviewId, action: "cancel" }).catch(() => {});
    }
  }
  registered = next;
  return () => {
    if (registered !== next) return;
    registered = undefined;
    for (const [reviewId, owner] of pending) {
      if (owner !== next) continue;
      pending.delete(reviewId);
      void owner.decide({ reviewId, action: "cancel" }).catch(() => {});
    }
  };
}

export function canReviewAttestationVersions(): boolean {
  return operations() !== undefined;
}

export function canConfigureAttestationAuthentication(): boolean {
  const bridge = desktopBridge();
  return bridge?.getClientPlatform() === "linux" && !!bridge.configureAttestationAuthentication;
}

export async function configureAttestationAuthentication(): Promise<boolean> {
  const bridge = desktopBridge();
  if (!canConfigureAttestationAuthentication() || !bridge?.configureAttestationAuthentication)
    throw new Error("System authentication does not need this setup on this platform.");
  return bridge.configureAttestationAuthentication();
}

export async function reviewAttestationVersions(origin: string) {
  const target = new URL(origin);
  if (
    !["http:", "https:"].includes(target.protocol) ||
    target.origin !== origin ||
    target.username ||
    target.password
  )
    throw new Error("Invalid version review environment.");
  const owner = operations();
  if (!owner) throw new Error("Use an installed T3 Attested client to review and approve builds.");
  const result = await owner.review(origin);
  for (const review of result) {
    if (review.origin !== origin) throw new Error("Version review belongs to another environment.");
    while (pending.size >= 32) {
      const oldest = pending.entries().next().value!;
      pending.delete(oldest[0]);
      void oldest[1].decide({ reviewId: oldest[0], action: "cancel" }).catch(() => {});
    }
    pending.set(review.id, owner);
  }
  return result;
}

export async function decideAttestationVersion(decision: AttestationVersionDecision) {
  const owner = pending.get(decision.reviewId);
  if (!owner) {
    if (decision.action === "cancel") return "cancelled" as const;
    throw new Error("Review this version again before changing approval.");
  }
  // Keep the owner during native authentication so closing the review can cancel that same operation.
  try {
    return await owner.decide(decision);
  } finally {
    pending.delete(decision.reviewId);
  }
}

/** A refreshed one-use review may replace an expired token only for the same displayed decision. */
export function sameReviewedVersion(
  a: AttestationVersionReview,
  b: AttestationVersionReview,
): boolean {
  return (
    a.origin === b.origin &&
    a.component === b.component &&
    a.targetOrigin === b.targetOrigin &&
    a.binding === b.binding &&
    a.vendor === b.vendor &&
    a.version === b.version &&
    a.fingerprint === b.fingerprint &&
    a.previousVersion === b.previousVersion &&
    a.previousFingerprint === b.previousFingerprint &&
    a.eligible === b.eligible &&
    a.approvalState === b.approvalState
  );
}
