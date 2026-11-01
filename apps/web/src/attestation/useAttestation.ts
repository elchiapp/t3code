import type { EnvironmentId, ThreadId } from "@t3tools/contracts";
import { useEnvironmentHttpBaseUrl } from "../state/environments";
import { useOriginAttestation } from "./useOriginAttestation";
export function useAttestation(environmentId: EnvironmentId, threadId: ThreadId | null) {
  return useOriginAttestation(useEnvironmentHttpBaseUrl(environmentId), threadId);
}
