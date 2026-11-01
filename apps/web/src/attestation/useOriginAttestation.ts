import { useSyncExternalStore } from "react";
import {
  clientAttestation,
  normalizeAttestationOrigin,
  unavailableAttestation,
} from "@t3tools/client-runtime/attestation";
const noEnvironment = unavailableAttestation("", "Connect an environment to verify it.");

export function useOriginAttestation(baseUrl: string | null, threadId: string | null = null) {
  let origin = "";
  try {
    if (baseUrl) origin = normalizeAttestationOrigin(baseUrl);
  } catch {}
  const subscribe = (listener: () => void) =>
    origin ? clientAttestation.subscribe(origin, listener) : () => {};
  const snapshot = () => (origin ? clientAttestation.get(origin) : noEnvironment);
  const status = useSyncExternalStore(subscribe, snapshot, () => noEnvironment);
  const canSend = origin !== "" && clientAttestation.canSend(origin);
  const overrideAccepted =
    origin !== "" && threadId !== null && clientAttestation.hasOverride(origin, threadId);
  return {
    origin,
    status,
    canSend,
    overrideAccepted,
    requiresOverride: origin !== "" && !canSend && !overrideAccepted && status.phase !== "checking",
    isCurrent: () =>
      canSend ||
      (origin !== "" && threadId !== null && clientAttestation.hasOverride(origin, threadId)),
    retry: () => {
      if (origin) void clientAttestation.refresh(origin);
    },
    override: () => {
      if (origin && threadId !== null) clientAttestation.override(origin, threadId);
    },
  };
}
