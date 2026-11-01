import { useSyncExternalStore } from "react";
import {
  clientAttestation,
  normalizeAttestationOrigin,
  unavailableAttestation,
} from "@t3tools/client-runtime/attestation";
const noEnvironment = unavailableAttestation("", "Connect an environment to verify it.");

export function useOriginAttestation(baseUrl: string | null) {
  let origin = "";
  try {
    if (baseUrl) origin = normalizeAttestationOrigin(baseUrl);
  } catch {}
  const subscribe = (listener: () => void) =>
    origin ? clientAttestation.subscribe(origin, listener) : () => {};
  const snapshot = () => (origin ? clientAttestation.get(origin) : noEnvironment);
  const status = useSyncExternalStore(subscribe, snapshot, () => noEnvironment);
  return {
    origin,
    status,
    canSend: origin !== "" && status.phase === "verified",
    isCurrent: () => origin !== "" && clientAttestation.canSend(origin),
    retry: () => {
      if (origin) void clientAttestation.refresh(origin);
    },
  };
}
