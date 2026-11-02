import { useSyncExternalStore } from "react";
import {
  clientAttestation,
  normalizeAttestationOrigin,
  unavailableAttestation,
} from "@t3tools/client-runtime/attestation";
import { readLocalApi } from "../localApi";

clientAttestation.setOverrideConfirmation(
  async ({ origin }) =>
    (await readLocalApi()?.dialogs.confirm(
      `Some required attestation checks did not pass: ${origin}\n\nSend anyway? Your approval applies only to this conversation until you close the app.`,
    )) ?? false,
);
const noEnvironment = unavailableAttestation("", "Connect an environment to verify it.");

export function useOriginAttestation(
  baseUrl: string | null,
  threadId: string | null = null,
  instanceId?: string,
) {
  let origin = "";
  try {
    if (baseUrl) origin = normalizeAttestationOrigin(baseUrl);
  } catch {}
  const subscribe = (listener: () => void) => {
    if (origin && threadId) clientAttestation.setInferenceProvider(origin, threadId, instanceId);
    return origin ? clientAttestation.subscribe(origin, listener) : () => {};
  };
  const snapshot = () => (origin ? clientAttestation.get(origin, instanceId) : noEnvironment);
  const status = useSyncExternalStore(subscribe, snapshot, () => noEnvironment);
  const canSend = origin !== "" && status.phase === "verified";
  const overrideAccepted =
    origin !== "" && threadId !== null && clientAttestation.hasOverride(origin, threadId);
  return {
    origin,
    status,
    canSend,
    overrideAccepted,
    requiresOverride: origin !== "" && !canSend && !overrideAccepted && status.phase !== "checking",
    authorize: async () =>
      origin !== "" &&
      (await clientAttestation.authorizeWithOverride(origin, threadId, instanceId)).allowed,
    isCurrent: () =>
      canSend ||
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
