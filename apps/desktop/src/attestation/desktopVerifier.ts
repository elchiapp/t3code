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
});
export type DeviceAttestationPolicy = typeof Policy.Type;
const decodeDevicePolicy = Schema.decodeUnknownSync(Policy);
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
      policy = decodeDevicePolicy(await services.readPolicy());
    } catch {
      return failed("unavailable", "Device verification is not configured.");
    }
    try {
      const origin = originOf(request.origin);
      if (request.origin !== origin || !policy.allowedEnvironmentOrigins.includes(origin))
        return failed("unavailable", "Verification is not configured for this environment.");
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
        return failed("unavailable", "The verifier must run on this device.");
      if (new URL(policy.modelOrigin).protocol !== "https:")
        return failed("unavailable", "Inference verification requires HTTPS.");
      const read = async () => decodeProof(await services.readStatus(verifier.origin));
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
      if (
        !proof.ready ||
        !fresh ||
        proof.modelOrigin !== policy.modelOrigin ||
        !requiredChecks.every((key) => proof.checks[key]?.state === "verified") ||
        !/^[a-f0-9]{64}$/.test(proof.tlsSpkiSha256 ?? "")
      ) {
        return {
          ...failed(
            "failed",
            proof.checks.inference?.state === "approval_required"
              ? "Tinfoil release approval is required."
              : "Attestation failed. Sending requires an explicit override.",
          ),
          checks: proof.checks,
        };
      }
      const target = new URL(origin);
      if (target.protocol === "https:") {
        if ((await services.peerKey(origin)) !== proof.tlsSpkiSha256)
          return {
            ...failed("failed", "The environment connection key does not match the verified VM."),
            checks: {
              ...proof.checks,
              environment_connection: { state: "failed", detail: "TLS key mismatch" },
            },
          };
      } else if (!["127.0.0.1", "localhost", "[::1]"].includes(target.hostname)) {
        return failed("failed", "A remote environment requires HTTPS.");
      }
      return {
        origin,
        phase: "verified",
        message: "VM hardware and Tinfoil verified",
        verifiedAt: proof.verifiedAt ?? null,
        expiresAt: proof.expiresAt ?? null,
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
    } catch {
      return failed(
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
      if (!origin) return -2;
      const verify = createDesktopVerifier({ ...services, peerKey: async () => peerKey });
      return (await verify({ origin })).phase === "verified" ? 0 : -2;
    } catch {
      return -2;
    }
  };
}
