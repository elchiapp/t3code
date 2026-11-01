import type { AttestationRequest, AttestationStatus, DesktopBridge } from "@t3tools/contracts";
import * as Effect from "effect/Effect";

const REQUIRED_CHECKS = [
  "hardware",
  "tls_key_commitment",
  "inference",
  "environment_connection",
] as const;
const MAX_LEASE_MS = 60_000;

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

export class ClientAttestationGate {
  private readonly entries = new Map<string, Entry>();
  private readonly verify: (request: AttestationRequest) => Promise<AttestationStatus>;
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

  get(origin: string): AttestationStatus {
    const entry = this.entry(origin);
    if (entry.status.phase === "verified" && !this.canSend(origin)) {
      entry.status = {
        ...entry.status,
        phase: "expired",
        message: "Verification expired. Checking again before sending.",
      };
    }
    return entry.status;
  }

  canSend(origin: string): boolean {
    const entry = this.entry(origin);
    return (
      entry.status.phase === "verified" &&
      entry.status.origin === origin &&
      entry.status.expiresAt !== null &&
      this.now() < entry.status.expiresAt &&
      this.monotonic() < entry.deadline &&
      REQUIRED_CHECKS.every((key) => entry.status.checks[key]?.state === "verified")
    );
  }

  private emit(entry: Entry) {
    for (const listener of entry.listeners) listener();
  }

  async refresh(origin: string, force = true): Promise<AttestationStatus> {
    const entry = this.entry(origin);
    if (entry.pending) return entry.pending;
    const started = this.now();
    const monotonicStarted = this.monotonic();
    if (force || !this.canSend(origin)) {
      entry.status = { ...entry.status, phase: "checking", message: "Verifying connection…" };
    }
    entry.pending = (async () => {
      await Promise.resolve();
      try {
        const status = await this.verify({ origin, refresh: force });
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
        entry.status = {
          origin,
          phase: "failed",
          message: error instanceof Error ? error.message : "Verification failed.",
          verifiedAt: null,
          expiresAt: null,
          checks: {},
        };
        entry.deadline = 0;
      } finally {
        entry.pending = undefined;
        this.emit(entry);
        this.schedule(origin, entry);
      }
      return entry.status;
    })();
    this.emit(entry);
    return entry.pending;
  }

  async authorize(origin: string): Promise<void> {
    await this.refresh(origin, false);
    if (!this.canSend(origin)) throw new Error(this.get(origin).message);
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

  subscribe(origin: string, listener: () => void): () => void {
    const entry = this.entry(origin);
    entry.listeners.add(listener);
    if (!this.canSend(origin) && !entry.pending) void this.refresh(origin);
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
    return unavailableAttestation(
      request.origin,
      "This client has no trusted device verifier. Chat is disabled.",
    );
  return bridge.getAttestationStatus(request);
});
