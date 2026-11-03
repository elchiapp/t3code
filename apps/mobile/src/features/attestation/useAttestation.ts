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

export function useAttestation(
  environmentId: EnvironmentId,
  threadId: string | null = null,
  instanceId?: string,
) {
  const connection = usePreparedConnection(environmentId);
  let origin = "";
  try {
    if (Option.isSome(connection))
      origin = normalizeAttestationOrigin(connection.value.httpBaseUrl);
  } catch {}
  const subscribe = useCallback(
    (listener: () => void) => {
      if (origin && threadId) clientAttestation.setInferenceProvider(origin, threadId, instanceId);
      return origin ? clientAttestation.subscribe(origin, listener) : () => {};
    },
    [origin, threadId, instanceId],
  );
  const snapshot = useCallback(
    () => (origin ? clientAttestation.get(origin, instanceId) : noEnvironment),
    [origin, instanceId],
  );
  const status = useSyncExternalStore(subscribe, snapshot, () => noEnvironment);
  const overrideAccepted = useSyncExternalStore(
    subscribe,
    () => origin !== "" && threadId !== null && clientAttestation.hasOverride(origin, threadId),
    () => false,
  );
  return {
    status,
    canSend: origin !== "" && status.phase === "verified",
    overrideAccepted,
    authorize: async () =>
      origin !== "" &&
      (await clientAttestation.authorizeWithOverride(origin, threadId, instanceId)).allowed,
    isCurrent: () =>
      origin !== "" &&
      (clientAttestation.canProceed(origin, instanceId) ||
        (threadId !== null && clientAttestation.hasOverride(origin, threadId))),
    revokeOverride: () => {
      if (origin && threadId) clientAttestation.revokeOverride(origin, threadId);
    },
    retry: () => {
      if (!retryVerifierHost() && origin) void clientAttestation.refresh(origin);
    },
  };
}
