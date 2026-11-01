import { useCallback, useSyncExternalStore } from "react";
import * as Option from "effect/Option";
import type { EnvironmentId } from "@t3tools/contracts";
import {
  clientAttestation,
  normalizeAttestationOrigin,
  unavailableAttestation,
} from "@t3tools/client-runtime/attestation";
import { usePreparedConnection } from "../../state/session";
import { retryVerifierHost } from "./hostLifecycle";

const noEnvironment = unavailableAttestation("", "Connect an environment to verify it.");

export function useAttestation(environmentId: EnvironmentId) {
  const connection = usePreparedConnection(environmentId);
  let origin = "";
  try {
    if (Option.isSome(connection))
      origin = normalizeAttestationOrigin(connection.value.httpBaseUrl);
  } catch {}
  const subscribe = useCallback(
    (listener: () => void) => (origin ? clientAttestation.subscribe(origin, listener) : () => {}),
    [origin],
  );
  const snapshot = useCallback(
    () => (origin ? clientAttestation.get(origin) : noEnvironment),
    [origin],
  );
  const status = useSyncExternalStore(subscribe, snapshot, () => noEnvironment);
  return {
    status,
    canSend: origin !== "" && status.phase === "verified",
    isCurrent: () => origin !== "" && clientAttestation.canSend(origin),
    retry: () => {
      if (!retryVerifierHost() && origin) void clientAttestation.refresh(origin);
    },
  };
}
