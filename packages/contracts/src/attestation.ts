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

export const AttestationReviewLink = Schema.Struct({
  label: Schema.String,
  url: Schema.String,
  kind: Schema.Literals(["changes", "source", "evidence", "vendor"]),
});

export const AttestationVersionReview = Schema.Struct({
  id: Schema.String,
  origin: Schema.String,
  component: Schema.Literals(["vm-firmware", "inference-release"]),
  targetOrigin: Schema.String,
  binding: Schema.String,
  vendor: Schema.String,
  title: Schema.String,
  version: Schema.String,
  fingerprint: Schema.String,
  previousVersion: Schema.NullOr(Schema.String),
  previousFingerprint: Schema.NullOr(Schema.String),
  eligible: Schema.Boolean,
  approvalState: Schema.Literals(["approved", "required", "revoked", "rejected"]),
  explanation: Schema.String,
  changes: Schema.Array(Schema.String),
  links: Schema.Array(AttestationReviewLink),
  sourceAvailability: Schema.String,
  expiresAt: Schema.Number,
});
export type AttestationVersionReview = typeof AttestationVersionReview.Type;

export const AttestationVersionDecision = Schema.Struct({
  reviewId: Schema.String,
  action: Schema.Literals(["approve", "revoke", "cancel"]),
});
export type AttestationVersionDecision = typeof AttestationVersionDecision.Type;

export const DeviceVersionDecisionRecord = Schema.Struct({
  component: Schema.Literals(["vm-firmware", "inference-release"]),
  targetOrigin: Schema.String,
  binding: Schema.String,
  version: Schema.String,
  fingerprint: Schema.String,
  action: Schema.Literals(["approve", "revoke"]),
  decidedAt: Schema.Number,
});
export type DeviceVersionDecisionRecord = typeof DeviceVersionDecisionRecord.Type;
