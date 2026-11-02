import * as Schema from "effect/Schema";

export const AttestationRequest = Schema.Struct({
  origin: Schema.String,
  refresh: Schema.optionalKey(Schema.Boolean),
});
export type AttestationRequest = typeof AttestationRequest.Type;

export const AttestationCheck = Schema.Struct({
  state: Schema.String,
  detail: Schema.optionalKey(Schema.String),
});

export const AttestationStatus = Schema.Struct({
  origin: Schema.String,
  phase: Schema.Literals(["checking", "verified", "failed", "expired", "unavailable"]),
  message: Schema.String,
  verifiedAt: Schema.NullOr(Schema.Number),
  expiresAt: Schema.NullOr(Schema.Number),
  checks: Schema.Record(Schema.String, AttestationCheck),
  targets: Schema.optionalKey(
    Schema.Struct({
      vmOrigin: Schema.String,
      proxyOrigin: Schema.String,
      inferenceOrigin: Schema.optionalKey(Schema.String),
      inferenceProviderIds: Schema.Array(Schema.String),
    }),
  ),
});
export type AttestationStatus = typeof AttestationStatus.Type;
