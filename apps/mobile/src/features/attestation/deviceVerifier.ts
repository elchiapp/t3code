import type { AttestationRequest, AttestationStatus } from "@t3tools/contracts";

export interface MobileProofPolicy {
  readonly modelOrigin: string;
  readonly proofOrigin: string;
  readonly environmentOrigins: ReadonlyArray<string>;
  readonly tlsSpkiSha256: string;
}

export interface MobileProofOperations {
  readonly policy: MobileProofPolicy;
  readonly transportProtected: () => Promise<boolean>;
  readonly prepare: () => Promise<{
    readonly nonce: string;
    readonly challenge: Readonly<Record<string, unknown>>;
    readonly expiresAt: number;
  }>;
  readonly collect: (input: unknown) => Promise<unknown>;
  readonly verifyHardware: (challenge: unknown, evidence: unknown) => Promise<void>;
  readonly verifyInference: () => Promise<{ readonly state: string; readonly detail: string }>;
}

export function createMobileDeviceVerifier(
  operations: MobileProofOperations,
  now = Date.now,
  monotonic = () => performance.now(),
) {
  let accepted: AttestationStatus | undefined;
  let acceptedDeadline = 0;
  let pending: Promise<AttestationStatus> | undefined;
  return async (request: AttestationRequest): Promise<AttestationStatus> => {
    const failure = (message: string): AttestationStatus => {
      accepted = undefined;
      acceptedDeadline = 0;
      return {
        origin: request.origin,
        phase: "failed",
        message,
        verifiedAt: null,
        expiresAt: null,
        checks: {},
      };
    };
    const policy = operations.policy;
    let origin: string;
    try {
      const url = new URL(request.origin);
      if (
        url.protocol !== "https:" ||
        url.username ||
        url.password ||
        url.origin !== request.origin
      )
        return failure("The VM connection must use its approved HTTPS origin.");
      origin = url.origin;
      if (
        !policy.environmentOrigins.includes(origin) ||
        !/^[a-f0-9]{64}$/.test(policy.tlsSpkiSha256)
      )
        return failure("This environment has no trusted device policy.");
      if (!(await operations.transportProtected()))
        return failure("Native connection protection is unavailable. Sending is blocked.");
    } catch {
      return failure("Device verification is unavailable. Sending is blocked.");
    }
    if (
      !request.refresh &&
      accepted?.origin === origin &&
      (accepted.expiresAt ?? 0) > now() + 10_000 &&
      monotonic() < acceptedDeadline
    )
      return accepted;
    if (pending) {
      const result = await pending;
      return result.origin === origin
        ? result
        : failure("Verification belongs to another environment.");
    }
    accepted = undefined;
    const started = now();
    const startedMonotonic = monotonic();
    pending = (async () => {
      let stage = "Creating the proof challenge";
      try {
        const prepared = await operations.prepare();
        if (
          !Number.isSafeInteger(prepared.expiresAt) ||
          prepared.expiresAt > now() + 60_000 ||
          prepared.expiresAt <= now()
        )
          return failure("The verification challenge is not fresh.");
        stage = "Collecting VM hardware evidence";
        const evidence = await operations.collect({
          version: 1,
          modelOrigin: policy.modelOrigin,
          tlsSpkiSha256: policy.tlsSpkiSha256,
          nonce: prepared.nonce,
          challenge: prepared.challenge,
        });
        stage = "Checking VM hardware evidence";
        await operations.verifyHardware(prepared.challenge, evidence);
        stage = "Checking Tinfoil evidence";
        const inference = await operations.verifyInference();
        if (inference.state !== "verified")
          return { ...failure(inference.detail), checks: { inference } };
        if (prepared.expiresAt <= now() || !(await operations.transportProtected()))
          return failure("Verification expired or connection protection changed.");
        accepted = {
          origin,
          phase: "verified",
          message:
            "Required VM hardware and Tinfoil checks passed. Full VM verification is incomplete.",
          verifiedAt: now(),
          expiresAt: prepared.expiresAt,
          checks: {
            hardware: {
              state: "verified",
              detail:
                "This phone checked the fresh hardware signature and approved firmware policy.",
            },
            tls_key_commitment: {
              state: "verified",
              detail: "The hardware proof commits to the VM connection key pinned by this app.",
            },
            environment_connection: {
              state: "verified",
              detail: "Native HTTPS and WebSocket connections enforce the same VM key.",
            },
            inference,
            proxy_workload: {
              state: "not_configured",
              detail: "The VM software is not independently measured.",
            },
            key_custody: {
              state: "not_configured",
              detail: "Exclusive private-key custody is not proved.",
            },
            inference_route: {
              state: "not_configured",
              detail: "The VM's actual inference routing is not independently proved.",
            },
          },
        };
        acceptedDeadline = startedMonotonic + Math.max(0, prepared.expiresAt - started);
        return accepted;
      } catch (cause) {
        accepted = undefined;
        const detail = cause instanceof Error ? cause.message.slice(0, 200) : "Verification failed";
        return failure(`${stage}: ${detail}. Sending is blocked.`);
      } finally {
        pending = undefined;
      }
    })();
    return pending;
  };
}
