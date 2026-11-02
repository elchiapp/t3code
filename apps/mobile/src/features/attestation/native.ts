import { requireOptionalNativeModule } from "expo";
import { Platform } from "react-native";
import * as Schema from "effect/Schema";
import type { MobileProofPolicy } from "./deviceVerifier";

interface NativeAttestation {
  policy(): unknown;
  transportProtected(): boolean;
}

export interface BundledMobilePolicy extends MobileProofPolicy {
  readonly verifierSha256: string;
}

const native = requireOptionalNativeModule<NativeAttestation>("T3Attestation");
const decodePolicy = Schema.decodeUnknownSync(
  Schema.Struct({
    environmentOrigins: Schema.Array(Schema.String),
    proofOrigin: Schema.String,
    modelOrigin: Schema.String,
    inferenceOrigin: Schema.optionalKey(Schema.String),
    tlsSpkiSha256: Schema.String,
    verifierSha256: Schema.String,
    inferenceProviderIds: Schema.optionalKey(Schema.Array(Schema.String)),
  }),
);

export function readBundledMobilePolicy(): BundledMobilePolicy {
  if (!native) throw new Error("The native attestation module is missing.");
  const raw = native.policy();
  const policy = decodePolicy(typeof raw === "string" ? JSON.parse(raw) : raw);
  if (
    !policy ||
    !Array.isArray(policy.environmentOrigins) ||
    !/^[a-f0-9]{64}$/.test(policy.verifierSha256 ?? "") ||
    !/^[a-f0-9]{64}$/.test(policy.tlsSpkiSha256 ?? "")
  )
    throw new Error("The signed app has no trusted verification policy.");
  return policy;
}

export function nativeTransportProtected(): boolean {
  return ["ios", "android"].includes(Platform.OS) && native?.transportProtected() === true;
}
