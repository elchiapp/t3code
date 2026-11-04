import type { AttestationRequest, AttestationStatus } from "@t3tools/contracts";
import * as Schema from "effect/Schema";

const Check = Schema.Struct({ state: Schema.String, detail: Schema.optionalKey(Schema.String) });
const LocalProof = Schema.Struct({
  ready: Schema.Boolean,
  verifiedAt: Schema.optionalKey(Schema.Number),
  expiresAt: Schema.optionalKey(Schema.Number),
  modelOrigin: Schema.optionalKey(Schema.String),
  tlsSpkiSha256: Schema.optionalKey(Schema.String),
  checks: Schema.Record(Schema.String, Check),
});
const Policy = Schema.Struct({
  verifierOrigin: Schema.String,
  modelOrigin: Schema.String,
  allowedEnvironmentOrigins: Schema.Array(Schema.String),
  tlsSpkiSha256: Schema.optionalKey(Schema.String),
  inferenceProviderIds: Schema.optionalKey(Schema.Array(Schema.String)),
  inferenceOrigin: Schema.optionalKey(Schema.String),
});
export type DeviceAttestationPolicy = typeof Policy.Type;
export const decodeDevicePolicy = Schema.decodeUnknownSync(Policy);
const decodeProof = Schema.decodeUnknownSync(LocalProof);

const requiredChecks = ["hardware", "tls_key_commitment", "inference"] as const;
const originOf = (raw: string) => {
  const url = new URL(raw);
  if (url.username || url.password || !["http:", "https:"].includes(url.protocol))
    throw new Error("Invalid verification origin");
  return url.origin;
};

export function createDesktopVerifier(services: {
  readPolicy: () => Promise<unknown>;
  readStatus: (verifierOrigin: string) => Promise<unknown>;
  refresh: (verifierOrigin: string) => Promise<void>;
  peerKey: (origin: string) => Promise<string>;
  now?: () => number;
}) {
  const now = services.now ?? Date.now;
  return async (request: AttestationRequest): Promise<AttestationStatus> => {
    const failed = (phase: "failed" | "unavailable", message: string): AttestationStatus => ({
      origin: request.origin,
      phase,
      message,
      verifiedAt: null,
      expiresAt: null,
      checks: {},
    });
    let policy: DeviceAttestationPolicy;
    try {
      const raw = await services.readPolicy();
      if (raw === null)
        return {
          ...failed("unavailable", "Device verification is not configured."),
          checks: {
            environment_connection: { state: "not_configured" },
            inference: { state: "not_configured" },
          },
        };
      policy = decodeDevicePolicy(raw);
    } catch {
      return {
        ...failed("failed", "The device verification policy is invalid or could not be read."),
        checks: { configuration: { state: "failed" } },
      };
    }
    const targets = {
      vmOrigin:
        policy.allowedEnvironmentOrigins.find((value) => {
          const url = new URL(value);
          return url.protocol === "https:" && url.hostname === new URL(policy.modelOrigin).hostname;
        }) ?? policy.modelOrigin,
      proxyOrigin: policy.modelOrigin,
      ...(policy.inferenceOrigin ? { inferenceOrigin: policy.inferenceOrigin } : {}),
      inferenceProviderIds: policy.inferenceProviderIds ?? ["tinfoil"],
    };
    const failure = (phase: "failed" | "unavailable", message: string): AttestationStatus => ({
      ...failed(phase, message),
      targets,
    });
    try {
      const origin = originOf(request.origin);
      if (request.origin !== origin) return failure("failed", "Invalid environment origin.");
      const environmentCovered = policy.allowedEnvironmentOrigins.includes(origin);
      if (!environmentCovered && !policy.inferenceOrigin)
        return {
          ...failure("unavailable", "Verification is not configured for this environment."),
          checks: {
            environment_connection: { state: "not_configured" },
          },
        };
      const verifier = new URL(policy.verifierOrigin);
      // The VM cannot choose a verifier or supply a ready flag for the client.
      if (
        verifier.protocol !== "http:" ||
        verifier.hostname !== "127.0.0.1" ||
        verifier.username ||
        verifier.password ||
        verifier.pathname !== "/" ||
        verifier.search ||
        verifier.hash
      )
        return failure("unavailable", "The verifier must run on this device.");
      if (new URL(policy.modelOrigin).protocol !== "https:")
        return failure("unavailable", "Inference verification requires HTTPS.");
      const read = async (): Promise<typeof LocalProof.Type> => {
        const proof = decodeProof(await services.readStatus(verifier.origin));
        return {
          ...proof,
          checks: {
            ...proof.checks,
            ...Object.fromEntries(
              (policy.inferenceProviderIds ?? ["tinfoil"]).flatMap((id) =>
                proof.checks.inference ? [[`inference:${id}`, proof.checks.inference]] : [],
              ),
            ),
          },
        };
      };
      let proof = await read();
      if (request.refresh || !proof.ready || (proof.expiresAt ?? 0) <= now() + 10_000) {
        await services.refresh(verifier.origin);
        proof = await read();
      }
      const fresh =
        proof.verifiedAt !== undefined &&
        Number.isSafeInteger(proof.verifiedAt) &&
        proof.verifiedAt <= now() + 30_000 &&
        proof.expiresAt !== undefined &&
        Number.isSafeInteger(proof.expiresAt) &&
        proof.expiresAt > now() &&
        proof.expiresAt - proof.verifiedAt <= 60_000;
      const targetMatches =
        proof.modelOrigin === policy.modelOrigin &&
        /^[a-f0-9]{64}$/.test(proof.tlsSpkiSha256 ?? "") &&
        (policy.tlsSpkiSha256 === undefined || proof.tlsSpkiSha256 === policy.tlsSpkiSha256);
      const target = new URL(origin);
      const connectionVerified =
        fresh && targetMatches && proof.checks.tls_key_commitment?.state === "verified";
      if (
        environmentCovered &&
        connectionVerified &&
        target.protocol === "https:" &&
        (await services.peerKey(origin)) !== proof.tlsSpkiSha256
      )
        return {
          ...failure("failed", "The environment connection key does not match the verified VM."),
          checks: {
            ...proof.checks,
            environment_connection: { state: "failed", detail: "TLS key mismatch" },
          },
        };
      if (
        environmentCovered &&
        target.protocol !== "https:" &&
        !["127.0.0.1", "localhost", "[::1]"].includes(target.hostname)
      )
        return failure("failed", "A remote environment requires HTTPS.");
      if (!environmentCovered)
        proof = {
          ...proof,
          checks: {
            ...proof.checks,
            environment_connection: {
              state: "not_configured",
              detail:
                "This environment is not attested. The VM proof covers only the configured inference proxy.",
            },
          },
        };
      if (connectionVerified && environmentCovered)
        proof = {
          ...proof,
          checks: {
            ...proof.checks,
            environment_connection: {
              state: "verified",
              detail:
                target.protocol === "https:"
                  ? "Selected environment TLS key matches the VM proof"
                  : "Explicitly trusted loopback environment",
            },
          },
        };
      if (
        !proof.ready ||
        !fresh ||
        !targetMatches ||
        !requiredChecks.every((key) => proof.checks[key]?.state === "verified")
      ) {
        const rejectedState = !targetMatches
          ? "failed"
          : (proof.expiresAt ?? 0) <= now()
            ? "expired"
            : "unavailable";
        const rejectedDetail = !targetMatches
          ? "Evidence does not match the approved endpoint and connection key."
          : "This receipt is not fresh. Check again before relying on it.";
        return {
          ...failure(
            "failed",
            proof.checks.hardware?.state === "approval_required" ||
              proof.checks.inference?.state === "approval_required"
              ? "A changed TEE build requires approval. Open Review versions and confirm with system authentication."
              : "Attestation failed. Sending requires an explicit override.",
          ),
          verifiedAt: fresh && targetMatches ? (proof.verifiedAt ?? null) : null,
          expiresAt: fresh && targetMatches ? (proof.expiresAt ?? null) : null,
          checks:
            fresh && targetMatches
              ? proof.checks
              : Object.fromEntries(
                  Object.entries(proof.checks).map(([key, check]) => [
                    key,
                    check.state === "verified"
                      ? { state: rejectedState, detail: rejectedDetail }
                      : check,
                  ]),
                ),
        };
      }
      return {
        origin,
        phase: "verified",
        message: environmentCovered
          ? "Required platform and inference checks passed."
          : "Inference proxy and endpoint checks passed. This environment is not attested.",
        targets,
        verifiedAt: proof.verifiedAt ?? null,
        expiresAt: proof.expiresAt ?? null,
        checks: {
          ...proof.checks,
          environment_connection: environmentCovered
            ? {
                state: "verified",
                detail:
                  target.protocol === "https:"
                    ? "Selected environment TLS key matches the VM proof"
                    : "Explicitly trusted loopback environment",
              }
            : proof.checks.environment_connection!,
        },
      };
    } catch {
      return failure(
        "failed",
        "Device verification is unavailable. Sending requires an explicit override.",
      );
    }
  };
}

export function createCertificateVerifier(services: Parameters<typeof createDesktopVerifier>[0]) {
  return async (hostname: string, peerKey: string, certificateValid: boolean): Promise<number> => {
    if (!certificateValid) return -2;
    try {
      const policy = decodeDevicePolicy(await services.readPolicy());
      const origin = policy.allowedEnvironmentOrigins.find((value) => {
        const url = new URL(value);
        return url.protocol === "https:" && url.hostname === hostname;
      });
      if (!origin) return -3;
      if (policy.tlsSpkiSha256 !== undefined) {
        return /^[a-f0-9]{64}$/.test(policy.tlsSpkiSha256) && peerKey === policy.tlsSpkiSha256
          ? 0
          : -2;
      }
      const verify = createDesktopVerifier({ ...services, peerKey: async () => peerKey });
      return (await verify({ origin })).phase === "verified" ? 0 : -2;
    } catch {
      return -2;
    }
  };
}
