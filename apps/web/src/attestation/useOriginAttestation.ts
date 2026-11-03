import { useSyncExternalStore } from "react";
import {
  clientAttestation,
  normalizeAttestationOrigin,
  unavailableAttestation,
  requiresVersionApproval,
} from "@t3tools/client-runtime/attestation";
import { readLocalApi } from "../localApi";

clientAttestation.setOverrideConfirmation(
  async ({ origin, status }) =>
    (await readLocalApi()?.dialogs.confirm(
      `${status.message}\n\nEnvironment: ${origin}\n\nSend anyway? Your approval applies only to this conversation until you close the app.`,
    )) ?? false,
);
const noEnvironment = unavailableAttestation("", "Connect an environment to verify it.");

export function useOriginAttestation(
  baseUrl: string | null,
  threadId: string | null = null,
  instanceId?: string,
  observeOnly = false,
) {
  let origin = "";
  try {
    if (baseUrl) origin = normalizeAttestationOrigin(baseUrl);
  } catch {}
  const subscribe = (listener: () => void) => {
    if (origin && threadId) clientAttestation.setInferenceProvider(origin, threadId, instanceId);
    return origin
      ? observeOnly
        ? clientAttestation.observe(origin, listener)
        : clientAttestation.subscribe(origin, listener)
      : () => {};
  };
  const snapshot = () => (origin ? clientAttestation.get(origin, instanceId) : noEnvironment);
  const status = useSyncExternalStore(subscribe, snapshot, () => noEnvironment);
  const canSend = origin !== "" && status.phase === "verified";
  const overrideAccepted = useSyncExternalStore(
    subscribe,
    () => origin !== "" && threadId !== null && clientAttestation.hasOverride(origin, threadId),
    () => false,
  );
  return {
    origin,
    status,
    canSend,
    overrideAccepted,
    requiresOverride:
      origin !== "" &&
      !clientAttestation.canProceed(origin, instanceId) &&
      !overrideAccepted &&
      status.phase !== "checking" &&
      !requiresVersionApproval(status),
    authorize: async () =>
      origin !== "" &&
      (await clientAttestation.authorizeWithOverride(origin, threadId, instanceId)).allowed,
    isCurrent: () =>
      (origin !== "" && clientAttestation.canProceed(origin, instanceId)) ||
      (origin !== "" && threadId !== null && clientAttestation.hasOverride(origin, threadId)),
    retry: () => {
      if (origin) void clientAttestation.refresh(origin);
    },
    override: () => {
      if (origin && threadId !== null) clientAttestation.override(origin, threadId);
    },
    revokeOverride: () => {
      if (origin && threadId !== null) clientAttestation.revokeOverride(origin, threadId);
    },
  };
}
