import type { AttestationRequest, AttestationStatus } from "@t3tools/contracts";

export interface MobileProofPolicy {
  readonly modelOrigin: string;
  readonly proofOrigin: string;
  readonly environmentOrigins: ReadonlyArray<string>;
  readonly tlsSpkiSha256: string;
  readonly inferenceProviderIds?: ReadonlyArray<string>;
  readonly inferenceOrigin?: string;
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
  readonly verifyHardware: (
    challenge: unknown,
    evidence: unknown,
  ) => Promise<{
    readonly state: "verified" | "approval_required";
    readonly detail?: string;
  }>;
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
        targets: {
          vmOrigin: operations.policy.environmentOrigins[0] ?? operations.policy.modelOrigin,
          proxyOrigin: operations.policy.modelOrigin,
          ...(operations.policy.inferenceOrigin
            ? { inferenceOrigin: operations.policy.inferenceOrigin }
            : {}),
          inferenceProviderIds: operations.policy.inferenceProviderIds ?? ["tinfoil"],
        },
      };
    };
    const policy = operations.policy;
    let origin: string;
    try {
      const url = new URL(request.origin);
      if (
        !["http:", "https:"].includes(url.protocol) ||
        url.username ||
        url.password ||
        url.origin !== request.origin
      )
        return failure("The environment must use a valid HTTP or HTTPS origin.");
      origin = url.origin;
      if (!policy.environmentOrigins.includes(origin))
        return {
          ...failure("Attestation is not configured for this environment."),
          phase: "unavailable",
          checks: { environment_connection: { state: "not_configured" } },
        };
      if (url.protocol !== "https:" || !/^[a-f0-9]{64}$/.test(policy.tlsSpkiSha256))
        return failure("The VM connection must use its approved HTTPS origin and key.");
      if (!(await operations.transportProtected()))
        return failure(
          "Native connection protection is unavailable. Sending requires confirmation.",
        );
    } catch {
      return failure("Device verification is unavailable. Sending requires confirmation.");
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
      try {
        const [platform, inferenceResult] = await Promise.allSettled([
          (async () => {
            const prepared = await operations.prepare();
            if (
              !Number.isSafeInteger(prepared.expiresAt) ||
              prepared.expiresAt > now() + 60_000 ||
              prepared.expiresAt <= now()
            )
              throw new Error("The verification challenge is not fresh.");
            const evidence = await operations.collect({
              version: 1,
              modelOrigin: policy.modelOrigin,
              tlsSpkiSha256: policy.tlsSpkiSha256,
              nonce: prepared.nonce,
              challenge: prepared.challenge,
            });
            const hardware = await operations.verifyHardware(prepared.challenge, evidence);
            if (prepared.expiresAt <= now() || !(await operations.transportProtected()))
              throw new Error("VM verification expired or connection protection changed.");
            return { expiresAt: prepared.expiresAt, hardware };
          })(),
          operations.verifyInference(),
        ]);
        const detail = (cause: unknown) =>
          cause instanceof Error ? cause.message.slice(0, 200) : "Verification failed.";
        const inference =
          inferenceResult.status === "fulfilled"
            ? inferenceResult.value
            : {
                state: "failed",
                detail: detail(inferenceResult.reason),
              };
        if (!(await operations.transportProtected()))
          return failure("Native connection protection changed. Sending requires confirmation.");
        const freshPlatform = platform.status === "fulfilled" && platform.value.expiresAt > now();
        const approvedPlatform =
          freshPlatform &&
          platform.status === "fulfilled" &&
          platform.value.hardware.state === "verified";
        const checks: AttestationStatus["checks"] = {
          hardware: freshPlatform
            ? platform.status === "fulfilled"
              ? platform.value.hardware
              : { state: "failed" }
            : {
                state: "failed",
                detail:
                  platform.status === "rejected" ? detail(platform.reason) : "VM evidence expired.",
              },
          tls_key_commitment: {
            state: freshPlatform ? "verified" : "unavailable",
            detail: "The VM hardware proof must commit to the key pinned by this app.",
          },
          environment_connection: {
            state: freshPlatform ? "verified" : "unavailable",
            detail: "Native HTTPS and WebSocket connections enforce the approved VM key.",
          },
          inference,
          ...Object.fromEntries(
            (policy.inferenceProviderIds ?? ["tinfoil"]).map((id) => [
              `inference:${id}`,
              inference,
            ]),
          ),
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
            detail: "Actual inference routing is not independently proved.",
          },
        };
        if (!approvedPlatform || inference.state !== "verified")
          return {
            ...failure(
              checks.hardware?.state === "approval_required" ||
                inference.state === "approval_required"
                ? "A changed TEE build requires approval. Open Review versions and confirm with system authentication."
                : "Required platform or inference checks did not pass. Sending requires confirmation.",
            ),
            verifiedAt: freshPlatform ? now() : null,
            expiresAt:
              platform.status === "fulfilled" && freshPlatform ? platform.value.expiresAt : null,
            checks,
          };
        accepted = {
          origin,
          phase: "verified",
          message:
            "Required platform and inference checks passed. Full VM verification is incomplete.",
          verifiedAt: now(),
          expiresAt: platform.value.expiresAt,
          targets: {
            vmOrigin: origin,
            proxyOrigin: policy.modelOrigin,
            ...(policy.inferenceOrigin ? { inferenceOrigin: policy.inferenceOrigin } : {}),
            inferenceProviderIds: policy.inferenceProviderIds ?? ["tinfoil"],
          },
          checks,
        };
        acceptedDeadline = startedMonotonic + Math.max(0, platform.value.expiresAt - started);
        return accepted;
      } catch (cause) {
        accepted = undefined;
        return failure(
          cause instanceof Error ? cause.message.slice(0, 200) : "Device verification failed.",
        );
      } finally {
        pending = undefined;
      }
    })();
    return pending;
  };
}
