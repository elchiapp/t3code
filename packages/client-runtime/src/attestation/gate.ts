import type { AttestationRequest, AttestationStatus, DesktopBridge } from "@t3tools/contracts";
import * as Effect from "effect/Effect";
export { withClientAttestationThread } from "./commands.ts";
export { attestationReport, type AttestationProvider } from "./report.ts";
export {
  canReviewAttestationVersions,
  reviewAttestationVersions,
  decideAttestationVersion,
  registerDeviceVersionOperations,
  canConfigureAttestationAuthentication,
  configureAttestationAuthentication,
  type DeviceVersionOperations,
} from "./versions.ts";
export { createDeviceApprovalController, type DeviceVersionDecisionRecord } from "./approvals.ts";
export { createProofCollector } from "./proofCollector.mjs";

const REQUIRED_CHECKS = [
  "hardware",
  "tls_key_commitment",
  "inference",
  "environment_connection",
] as const;
const MAX_LEASE_MS = 60_000;

export function requiresVersionApproval(status: AttestationStatus): boolean {
  const inference = status.checks.inference?.state;
  const environmentNeedsHardware = !status.targets || status.origin === status.targets.vmOrigin;
  const usesProxy = inference !== "not_offered" && inference !== "not_configured";
  return (
    inference === "approval_required" ||
    (status.checks.hardware?.state === "approval_required" &&
      (environmentNeedsHardware || usesProxy))
  );
}

const absent = (state?: string) => state === "not_offered" || state === "not_configured";
const localOrigin = (origin: string) => {
  try {
    return ["127.0.0.1", "localhost", "[::1]"].includes(new URL(origin).hostname);
  } catch {
    return false;
  }
};

export function unattestedReason(status: AttestationStatus): string | undefined {
  if (
    status.phase === "checking" &&
    !status.targets &&
    status.checks.inference?.state !== "not_offered"
  )
    return undefined;
  if (status.checks.inference?.state === "not_offered")
    return "The selected provider does not offer TEE attestation.";
  if (status.checks.inference?.state === "not_configured")
    return "Attestation is not configured for the selected provider.";
  if (absent(status.checks.environment_connection?.state))
    return "Attestation is not configured for this environment.";
  return undefined;
}

const protectedTarget = (status: AttestationStatus) =>
  !!status.targets &&
  (status.origin === status.targets.vmOrigin ||
    !["not_offered", "not_configured"].includes(
      status.checks.inference?.state ?? "not_configured",
    ));

export function normalizeAttestationOrigin(value: string): string {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error("Unsupported attestation target");
  }
  return url.origin;
}

export function unavailableAttestation(
  origin: string,
  message = "Device verification is unavailable.",
): AttestationStatus {
  return { origin, phase: "unavailable", message, verifiedAt: null, expiresAt: null, checks: {} };
}

interface Entry {
  status: AttestationStatus;
  deadline: number;
  pending: Promise<AttestationStatus> | undefined;
  listeners: Set<() => void>;
  timer: AbortController | undefined;
}

export interface AttestationAuthorization {
  readonly status: AttestationStatus;
  readonly allowed: boolean;
  readonly requiresOverride: boolean;
  readonly cancelled?: boolean;
}

export interface AttestationConfirmation {
  readonly origin: string;
  readonly threadId: string;
  readonly status: AttestationStatus;
}

export class ClientAttestationGate {
  private readonly versionReviewListeners = new Set<(origin: string) => void>();
  private readonly entries = new Map<string, Entry>();
  private readonly overriddenThreads = new Map<string, Set<string>>();
  private verify: (request: AttestationRequest) => Promise<AttestationStatus>;
  private generation = 0;
  private confirmOverride: ((request: AttestationConfirmation) => Promise<boolean>) | undefined;
  private readonly pendingConfirmations = new Map<string, Promise<boolean>>();
  private readonly threadProviders = new Map<string, string>();
  private readonly providerSnapshots = new WeakMap<
    AttestationStatus,
    Map<string, AttestationStatus>
  >();
  private readonly now: () => number;
  private readonly monotonic: () => number;
  constructor(
    verify: (request: AttestationRequest) => Promise<AttestationStatus>,
    now = Date.now,
    monotonic = () => performance.now(),
  ) {
    this.verify = verify;
    this.now = now;
    this.monotonic = monotonic;
  }

  setDeviceVerifier(verify: (request: AttestationRequest) => Promise<AttestationStatus>): void {
    this.generation++;
    this.verify = verify;
    this.overriddenThreads.clear();
    for (const [origin, entry] of this.entries) {
      entry.timer?.abort();
      entry.status = unavailableAttestation(
        origin,
        "Device verifier changed. Fresh verification is required.",
      );
      entry.deadline = 0;
      entry.pending = undefined;
      this.emit(entry);
      this.schedule(origin, entry);
    }
  }

  invalidate(): void {
    this.setDeviceVerifier(this.verify);
  }

  setOverrideConfirmation(
    confirm: ((request: AttestationConfirmation) => Promise<boolean>) | undefined,
  ): void {
    this.confirmOverride = confirm;
  }

  private entry(origin: string): Entry {
    let entry = this.entries.get(origin);
    if (!entry) {
      entry = {
        status: {
          ...unavailableAttestation(origin, "Checking device verification…"),
          phase: "checking",
        },
        deadline: 0,
        pending: undefined,
        listeners: new Set(),
        timer: undefined,
      };
      this.entries.set(origin, entry);
    }
    return entry;
  }

  setInferenceProvider(origin: string, threadId: string, instanceId: string | undefined): void {
    const key = JSON.stringify([origin, threadId]);
    if (instanceId) this.threadProviders.set(key, instanceId);
    else this.threadProviders.delete(key);
  }

  private providerStatus(status: AttestationStatus, instanceId?: string): AttestationStatus {
    if (!instanceId) return status;
    let snapshots = this.providerSnapshots.get(status);
    if (!snapshots) {
      snapshots = new Map();
      this.providerSnapshots.set(status, snapshots);
    }
    const cached = snapshots.get(instanceId);
    if (cached) return cached;
    const directCloud = instanceId === "codex" || instanceId === "claudeAgent";
    const configured = status.targets?.inferenceProviderIds.includes(instanceId) === true;
    const inference = status.checks[`inference:${instanceId}`] ?? {
      state: configured
        ? "unavailable"
        : directCloud
          ? "not_offered"
          : status.checks.configuration?.state === "failed"
            ? "failed"
            : "not_configured",
      detail: configured
        ? "Attestation is configured for this provider, but its verification is unavailable."
        : directCloud
          ? "This connection does not offer TEE attestation. This is not a verification failure."
          : "Independent inference verification is not configured for this provider.",
    };
    const uncovered = status.phase === "verified" && inference.state !== "verified";
    const unusedProxy = localOrigin(status.origin) && absent(inference.state);
    const snapshot: AttestationStatus = {
      ...status,
      phase: uncovered || unusedProxy ? "unavailable" : status.phase,
      message:
        uncovered || unusedProxy
          ? (inference.detail ?? "Inference verification did not pass for the selected provider.")
          : status.message,
      checks: { ...status.checks, inference },
    };
    snapshots.set(instanceId, snapshot);
    return snapshot;
  }

  get(origin: string, instanceId?: string): AttestationStatus {
    const entry = this.entry(origin);
    if (entry.status.phase === "verified" && !this.canSend(origin)) {
      entry.status = {
        ...entry.status,
        phase: "expired",
        message: "Verification expired. Checking again before sending.",
      };
    }
    return this.providerStatus(entry.status, instanceId);
  }

  canSend(origin: string, instanceId?: string): boolean {
    const entry = this.entry(origin);
    const status = this.providerStatus(entry.status, instanceId);
    return (
      status.phase === "verified" &&
      status.origin === origin &&
      status.expiresAt !== null &&
      this.now() < status.expiresAt &&
      this.monotonic() < entry.deadline &&
      REQUIRED_CHECKS.every((key) => status.checks[key]?.state === "verified")
    );
  }

  canProceed(origin: string, instanceId?: string): boolean {
    if (this.canSend(origin, instanceId)) return true;
    const entry = this.entry(origin);
    const status = this.providerStatus(entry.status, instanceId);
    if (!unattestedReason(status) || requiresVersionApproval(status)) return false;
    if (
      status.checks.configuration?.state === "failed" &&
      !(localOrigin(origin) && status.checks.inference?.state === "not_offered")
    )
      return false;
    const platformRequired =
      !localOrigin(origin) && !absent(status.checks.environment_connection?.state);
    const inferenceRequired = !absent(status.checks.inference?.state);
    const required = [
      ...(platformRequired ? ["hardware", "tls_key_commitment", "environment_connection"] : []),
      ...(inferenceRequired ? ["hardware", "tls_key_commitment", "inference"] : []),
    ];
    if (required.length === 0) return true;
    return (
      status.expiresAt !== null &&
      this.now() < status.expiresAt &&
      this.monotonic() < entry.deadline &&
      required.every((key) => status.checks[key]?.state === "verified")
    );
  }

  hasOverride(origin: string, threadId: string, instanceId?: string): boolean {
    const provider = instanceId ?? this.threadProviders.get(JSON.stringify([origin, threadId]));
    return (
      !requiresVersionApproval(this.providerStatus(this.entry(origin).status, provider)) &&
      this.overriddenThreads.get(origin)?.has(threadId) === true
    );
  }

  onVersionReviewRequired(listener: (origin: string) => void): () => void {
    this.versionReviewListeners.add(listener);
    return () => {
      this.versionReviewListeners.delete(listener);
    };
  }

  private versionApprovalBlocked(
    origin: string,
    status: AttestationStatus,
  ): AttestationAuthorization {
    for (const listener of this.versionReviewListeners) listener(origin);
    return {
      status: {
        ...status,
        message:
          "A changed TEE build needs approval. Open Review versions and confirm with system authentication.",
      },
      allowed: false,
      requiresOverride: false,
    };
  }

  override(origin: string, threadId: string): void {
    if (threadId === "") return;
    const entry = this.entry(origin);
    let threads = this.overriddenThreads.get(origin);
    if (!threads) {
      threads = new Set();
      this.overriddenThreads.set(origin, threads);
    }
    threads.add(threadId);
    entry.status = { ...entry.status };
    this.emit(entry);
  }

  revokeOverride(origin: string, threadId: string): void {
    if (!this.overriddenThreads.get(origin)?.delete(threadId)) return;
    const entry = this.entry(origin);
    entry.status = { ...entry.status };
    this.emit(entry);
  }

  moveOverride(origin: string, draftId: string, threadId: string): void {
    if (draftId === threadId) return;
    const threads = this.overriddenThreads.get(origin);
    if (!threads?.delete(draftId)) return;
    threads.add(threadId);
    const entry = this.entry(origin);
    entry.status = { ...entry.status };
    this.emit(entry);
  }

  private emit(entry: Entry) {
    for (const listener of entry.listeners) listener();
  }

  async refresh(origin: string, force = true): Promise<AttestationStatus> {
    const entry = this.entry(origin);
    if (entry.pending) return entry.pending;
    const started = this.now();
    const generation = this.generation;
    const monotonicStarted = this.monotonic();
    if (force || entry.status.phase === "checking") {
      entry.status = { ...entry.status, phase: "checking", message: "Verifying connection…" };
    }
    entry.pending = (async () => {
      await Promise.resolve();
      try {
        const status = await this.verify({ origin, refresh: force });
        if (generation !== this.generation) return entry.status;
        if (status.origin !== origin)
          throw new Error("Verification belongs to another environment.");
        if (
          status.phase === "verified" &&
          (status.verifiedAt === null ||
            !Number.isSafeInteger(status.verifiedAt) ||
            status.verifiedAt > this.now() + 30_000 ||
            status.expiresAt === null ||
            !Number.isSafeInteger(status.expiresAt) ||
            status.expiresAt <= this.now() ||
            !REQUIRED_CHECKS.every((key) => status.checks[key]?.state === "verified"))
        )
          throw new Error("Complete, fresh device verification is required.");
        const expiresAt =
          status.expiresAt === null ? null : Math.min(status.expiresAt, started + MAX_LEASE_MS);
        entry.status = { ...status, expiresAt };
        entry.deadline =
          monotonicStarted + (expiresAt === null ? 0 : Math.max(0, expiresAt - started));
      } catch (error) {
        if (generation !== this.generation) return entry.status;
        entry.status = {
          origin,
          phase: "failed",
          message: error instanceof Error ? error.message : "Verification failed.",
          verifiedAt: null,
          expiresAt: null,
          checks: {},
          ...(entry.status.targets ? { targets: entry.status.targets } : {}),
        };
        entry.deadline = 0;
      } finally {
        if (generation === this.generation) {
          entry.pending = undefined;
          this.emit(entry);
          this.schedule(origin, entry);
        }
      }
      return entry.status;
    })();
    this.emit(entry);
    return entry.pending;
  }

  async authorize(origin: string, threadId: string | null = null): Promise<void> {
    const authorization = await this.authorizeWithOverride(origin, threadId);
    if (!authorization.allowed)
      throw new Error(
        authorization.cancelled ? "Sending cancelled." : authorization.status.message,
      );
  }

  async authorizeWithOverride(
    origin: string,
    threadId: string | null,
    instanceId?: string,
  ): Promise<AttestationAuthorization> {
    const provider =
      instanceId ??
      (threadId ? this.threadProviders.get(JSON.stringify([origin, threadId])) : undefined);
    const initial = this.get(origin, provider);
    if (requiresVersionApproval(initial)) return this.versionApprovalBlocked(origin, initial);
    if (this.canProceed(origin, provider) && unattestedReason(initial) && !protectedTarget(initial))
      return { status: initial, allowed: true, requiresOverride: false };
    if (threadId && this.hasOverride(origin, threadId, provider)) {
      if (protectedTarget(initial)) await this.refresh(origin, true);
      else void this.refresh(origin, false);
      const status = this.get(origin, provider);
      if (requiresVersionApproval(status)) return this.versionApprovalBlocked(origin, status);
      return { status, allowed: true, requiresOverride: false };
    }
    const known = this.get(origin, provider);
    if (
      this.confirmOverride &&
      threadId &&
      known.phase !== "checking" &&
      !protectedTarget(known) &&
      !this.canSend(origin, provider)
    )
      void this.refresh(origin, false);
    else await this.refresh(origin, false);
    const refreshed = this.get(origin, provider);
    if (requiresVersionApproval(refreshed)) return this.versionApprovalBlocked(origin, refreshed);
    if (this.canProceed(origin, provider) && unattestedReason(refreshed))
      return { status: refreshed, allowed: true, requiresOverride: false };
    if (
      !this.canSend(origin, provider) &&
      threadId !== null &&
      threadId !== "" &&
      !this.hasOverride(origin, threadId, provider) &&
      this.confirmOverride
    ) {
      const key = JSON.stringify([origin, threadId]);
      let pending = this.pendingConfirmations.get(key);
      if (!pending) {
        const confirm = this.confirmOverride;
        const generation = this.generation;
        pending = Promise.resolve().then(async () => {
          if (this.canSend(origin, provider)) return true;
          const accepted = await confirm({
            origin,
            threadId,
            status: this.get(origin, provider),
          }).catch(() => false);
          if (!accepted || generation !== this.generation) return false;
          if (requiresVersionApproval(this.get(origin, provider))) return false;
          this.override(origin, threadId);
          return true;
        });
        this.pendingConfirmations.set(key, pending);
      }
      try {
        if (!(await pending)) {
          if (requiresVersionApproval(this.get(origin, provider)))
            return this.versionApprovalBlocked(origin, this.get(origin, provider));
          return {
            status: this.get(origin, provider),
            allowed: false,
            requiresOverride: !this.canSend(origin, provider),
            cancelled: true,
          };
        }
      } finally {
        if (this.pendingConfirmations.get(key) === pending) this.pendingConfirmations.delete(key);
      }
    }
    const status = this.get(origin, provider);
    if (requiresVersionApproval(status)) return this.versionApprovalBlocked(origin, status);
    const allowed =
      this.canSend(origin, provider) ||
      (threadId !== null && threadId !== "" && this.hasOverride(origin, threadId, provider));
    return { status, allowed, requiresOverride: !allowed };
  }

  private schedule(origin: string, entry: Entry) {
    entry.timer?.abort();
    if (entry.listeners.size === 0) return;
    const delay =
      entry.status.phase === "verified" && entry.status.expiresAt !== null
        ? Math.min(10_000, Math.max(1_000, entry.status.expiresAt - this.now() - 10_000))
        : 15_000;
    const timer = new AbortController();
    entry.timer = timer;
    void Effect.runPromise(
      Effect.sleep(delay).pipe(Effect.andThen(Effect.promise(() => this.refresh(origin, false)))),
      { signal: timer.signal },
    ).catch(() => {});
  }

  observe(origin: string, listener: () => void): () => void {
    const entry = this.entry(origin);
    entry.listeners.add(listener);
    return () => {
      entry.listeners.delete(listener);
      if (entry.listeners.size === 0) entry.timer?.abort();
    };
  }

  subscribe(origin: string, listener: () => void): () => void {
    const entry = this.entry(origin);
    entry.listeners.add(listener);
    if (!this.canSend(origin) && !entry.pending) void this.refresh(origin, false);
    else this.schedule(origin, entry);
    return () => {
      entry.listeners.delete(listener);
      if (entry.listeners.size === 0) entry.timer?.abort();
    };
  }
}

function desktopBridge(): DesktopBridge | undefined {
  return (globalThis as { window?: { desktopBridge?: DesktopBridge } }).window?.desktopBridge;
}

export const clientAttestation = new ClientAttestationGate(async (request) => {
  const bridge = desktopBridge();
  if (!bridge?.getAttestationStatus)
    return {
      ...unavailableAttestation(request.origin, "This client has no configured device verifier."),
      checks: {
        environment_connection: { state: "not_configured" },
        inference: { state: "not_configured" },
      },
    };
  return bridge.getAttestationStatus(request);
});

desktopBridge()?.onAttestationVersionsChanged?.(() => clientAttestation.invalidate());
