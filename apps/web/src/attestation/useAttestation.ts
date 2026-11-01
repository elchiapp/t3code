import type { EnvironmentId } from "@t3tools/contracts";
import { useEnvironmentHttpBaseUrl } from "../state/environments";
import { useOriginAttestation } from "./useOriginAttestation";
export function useAttestation(environmentId: EnvironmentId) {
  return useOriginAttestation(useEnvironmentHttpBaseUrl(environmentId));
}
