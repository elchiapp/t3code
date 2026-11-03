import type { AttestationStatus } from "@t3tools/contracts";

export const missingAttestation = (state?: string) =>
  state === "not_offered" || state === "not_configured";
export function localAttestationOrigin(origin: string): boolean {
  try {
    return ["127.0.0.1", "localhost", "[::1]"].includes(new URL(origin).hostname);
  } catch {
    return false;
  }
}

export function attestationScope(status: AttestationStatus) {
  const platform =
    !localAttestationOrigin(status.origin) &&
    !missingAttestation(status.checks.environment_connection?.state);
  const inference =
    !missingAttestation(status.checks.inference?.state) &&
    (status.checks.inference !== undefined || status.targets !== undefined);
  const proxy = inference && status.targets !== undefined;
  return {
    required: [
      ...new Set([
        ...(platform ? ["hardware", "tls_key_commitment", "environment_connection"] : []),
        ...(proxy ? ["hardware", "tls_key_commitment"] : []),
        ...(inference ? ["inference"] : []),
      ]),
    ],
    optional: [
      ...(platform || proxy ? ["proxy_workload", "key_custody"] : []),
      ...(inference ? ["inference_route"] : []),
    ],
  };
}

export function failedAttestation(status: AttestationStatus): boolean {
  const { required, optional } = attestationScope(status);
  const active = required.filter((key) => !missingAttestation(status.checks[key]?.state));
  const explicitFailure = (key: string) =>
    ["failed", "expired", "unavailable", "approval_required"].includes(
      status.checks[key]?.state ?? "",
    );
  if ([...active, ...optional].some(explicitFailure)) return true;
  if (status.phase === "checking") return false;
  if (status.checks.configuration?.state === "failed" && active.length > 0) return true;
  return (
    active.some((key) => status.checks[key]?.state !== "verified") ||
    (active.length > 0 &&
      (status.phase === "expired" || status.expiresAt === null || status.verifiedAt === null))
  );
}
