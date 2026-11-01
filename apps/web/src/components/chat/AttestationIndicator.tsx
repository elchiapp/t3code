import type { AttestationStatus } from "@t3tools/contracts";
import { Popover, PopoverTrigger, PopoverPopup } from "../ui/popover";
import { Button } from "../ui/button";
import { cn } from "~/lib/utils";

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
  const label = canSend
    ? "Attestation verified"
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
      data-attestation-state={status.phase}
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
              canSend
                ? "bg-success"
                : pending
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
            <p>{status.message}</p>
            <dl className="space-y-1">
              {(
                [
                  ["environment_connection", "Selected environment"],
                  ["hardware", "VM hardware"],
                  ["tls_key_commitment", "Connection key"],
                  ["inference", "Tinfoil release"],
                ] as const
              ).map(([key, title]) => (
                <div key={key} className="flex justify-between gap-4">
                  <dt>{title}</dt>
                  <dd>{status.checks[key]?.state ?? "not checked"}</dd>
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
