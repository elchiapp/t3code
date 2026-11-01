import type { AttestationStatus } from "@t3tools/contracts";
import { Popover, PopoverTrigger, PopoverPopup } from "../ui/popover";
import { Button } from "../ui/button";
import { cn } from "~/lib/utils";

const checks = [
  ["environment_connection", "Selected environment", ""],
  ["hardware", "VM hardware", ""],
  ["tls_key_commitment", "Connection key", ""],
  ["inference", "Tinfoil release", ""],
  ["proxy_workload", "VM software", "No accepted measurement of the software running on the VM."],
  [
    "key_custody",
    "Exclusive key custody",
    "No accepted proof that the private keys exist only inside the approved VM.",
  ],
  [
    "inference_route",
    "Inference routing",
    "No accepted proof of where the VM forwards the actual inference requests.",
  ],
] as const;

function checkLabel(state: string | undefined) {
  switch (state) {
    case "verified":
      return "Verified";
    case "failed":
      return "Failed";
    case "checking":
      return "Checking";
    case "approval_required":
      return "Approval required";
    default:
      return "Not verified";
  }
}

export function AttestationIndicator({
  status,
  canSend,
  onRetry,
}: {
  status: AttestationStatus;
  canSend: boolean;
  onRetry: () => void;
}) {
  const pending = status.phase === "checking";
  const complete = canSend && checks.every(([key]) => status.checks[key]?.state === "verified");
  const label = canSend
    ? complete
      ? "Attestation verified"
      : "Attestation incomplete"
    : pending
      ? "Verifying connection"
      : status.phase === "unavailable"
        ? "Verification unavailable"
        : status.phase === "expired"
          ? "Verification expired"
          : "Verification failed";
  return (
    <div
      className="flex h-6 items-center px-1 text-xs text-muted-foreground"
      data-attestation-state={canSend && !complete ? "partial" : status.phase}
    >
      <Popover>
        <PopoverTrigger
          render={
            <button
              type="button"
              className="inline-flex items-center gap-1.5 rounded px-1 py-0.5 text-xs"
              aria-label={label}
            />
          }
        >
          <span
            aria-hidden="true"
            className={cn(
              "size-1.5 rounded-full",
              complete
                ? "bg-success"
                : canSend || pending
                  ? "bg-warning"
                  : status.phase === "unavailable"
                    ? "bg-muted-foreground"
                    : "bg-error",
            )}
          />
          <span role="status" aria-live="polite">
            {label}
          </span>
        </PopoverTrigger>
        <PopoverPopup width="md" align="start">
          <div className="space-y-3 text-xs">
            <p>
              {canSend && !complete
                ? "Chat is enabled because the required checks passed. Full VM verification is incomplete."
                : status.message}
            </p>
            <dl className="space-y-1">
              {checks.map(([key, title, fallbackDetail]) => (
                <div key={key} className="grid grid-cols-[1fr_auto] gap-x-4 gap-y-1">
                  <dt>{title}</dt>
                  <dd>{checkLabel(status.checks[key]?.state)}</dd>
                  {(status.checks[key]?.detail || fallbackDetail) && (
                    <dd className="col-span-2 text-muted-foreground">
                      {status.checks[key]?.detail || fallbackDetail}
                    </dd>
                  )}
                </div>
              ))}
            </dl>
            <p>
              Checks run on this device. The VM software and administrator remain trusted. Other
              model providers do not become confidential.
            </p>
            <Button size="sm" variant="outline" onClick={onRetry} disabled={pending}>
              Check again
            </Button>
          </div>
        </PopoverPopup>
      </Popover>
    </div>
  );
}
