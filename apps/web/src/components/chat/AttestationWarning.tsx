import type { EnvironmentId } from "@t3tools/contracts";
import { unattestedReason } from "@t3tools/client-runtime/attestation";
import { Tooltip, TooltipTrigger, TooltipPopup } from "../ui/tooltip";
import { useAttestation } from "../../attestation/useAttestation";

export function AttestationWarning({
  environmentId,
  instanceId,
}: {
  environmentId: EnvironmentId;
  instanceId: string;
}) {
  const { status } = useAttestation(environmentId, null, instanceId, true);
  const reason = unattestedReason(status);
  return reason ? (
    <Tooltip>
      <TooltipTrigger
        render={
          <span role="img" aria-label={reason} className="mr-1 text-xs text-warning-foreground" />
        }
      >
        ⚠︎
      </TooltipTrigger>
      <TooltipPopup>{reason}</TooltipPopup>
    </Tooltip>
  ) : null;
}
