import type { AttestationStatus } from "@t3tools/contracts";
import { useEffect, useState } from "react";
import {
  clientAttestation,
  attestationReport,
  type AttestationProvider,
} from "@t3tools/client-runtime/attestation";
import { Popover, PopoverTrigger, PopoverPopup } from "../ui/popover";
import { Button } from "../ui/button";
import { cn } from "~/lib/utils";
import { AttestationVersionReview } from "./AttestationVersionReview";

export function AttestationIndicator({
  status,
  canSend,
  onRetry,
  overrideAccepted = false,
  onRevokeOverride,
  environmentLabel,
  provider,
}: {
  status: AttestationStatus;
  canSend: boolean;
  onRetry: () => void;
  overrideAccepted?: boolean;
  onRevokeOverride?: () => void;
  environmentLabel?: string | undefined;
  provider?: AttestationProvider | undefined;
}) {
  const [open, setOpen] = useState(false);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- A blocked send requests the native review popover through the shared authorization gate.
  useEffect(
    () =>
      clientAttestation.onVersionReviewRequired((origin) => {
        if (origin === status.origin) setOpen(true);
      }),
    [status.origin],
  );
  const report = attestationReport(status, canSend, environmentLabel, provider);
  const state =
    report.tone === "green"
      ? "verified"
      : report.tone === "yellow"
        ? "partial"
        : report.tone === "gray"
          ? "unavailable"
          : "failed";
  return (
    <div
      className="flex min-h-6 items-center px-1 text-xs text-muted-foreground"
      data-attestation-state={state}
    >
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger
          render={
            <button
              type="button"
              className="inline-flex items-center gap-1.5 rounded px-1 py-0.5 text-left text-xs"
              aria-label={report.label}
            />
          }
        >
          <span
            aria-hidden="true"
            className={cn(
              "size-1.5 shrink-0 rounded-full",
              report.tone === "green"
                ? "bg-success"
                : report.tone === "yellow"
                  ? "bg-warning"
                  : report.tone === "gray"
                    ? "bg-muted-foreground"
                    : "bg-error",
            )}
          />
          <span role="status" aria-live="polite">
            {report.label}
          </span>
        </PopoverTrigger>
        <PopoverPopup width="md" align="start">
          <div className="max-h-[min(75vh,42rem)] space-y-4 overflow-y-auto text-xs">
            <AttestationVersionReview
              key={status.targets?.vmOrigin ?? status.origin}
              origin={status.targets?.vmOrigin ?? status.origin}
              onChanged={onRetry}
            />
            {overrideAccepted && (
              <div className="space-y-2">
                <p>Unverified sending is allowed for this conversation until you close the app.</p>
                <Button size="sm" variant="outline" onClick={onRevokeOverride}>
                  Require verification
                </Button>
              </div>
            )}
            {report.sections.map((section) => (
              <section key={section.title} className="space-y-2 border-b pb-3 last:border-0">
                <h3 className="font-semibold">{section.title}</h3>
                <p className="font-medium">{section.name}</p>
                {section.origin && section.origin !== section.name && (
                  <p className="break-all text-muted-foreground">{section.origin}</p>
                )}
                <p>{section.summary}</p>
                {section.route && (
                  <p className="break-all text-muted-foreground">{section.route}</p>
                )}
                <dl className="space-y-3">
                  {section.rows.map((row) => (
                    <div key={row.title} className="grid grid-cols-[1fr_auto] gap-x-4 gap-y-1">
                      <dt>{row.title}</dt>
                      <dd className="inline-flex items-center gap-1.5 font-medium">
                        <span
                          aria-hidden="true"
                          data-attestation-tone={row.tone}
                          className={cn(
                            "size-1.5 shrink-0 rounded-full",
                            row.tone === "green"
                              ? "bg-success"
                              : row.tone === "red"
                                ? "bg-error"
                                : row.tone === "gray"
                                  ? "bg-muted-foreground"
                                  : "bg-warning",
                          )}
                        />
                        {row.result}
                      </dd>
                      <dd className="col-span-2 text-muted-foreground">{row.explanation}</dd>
                      {row.detail && (
                        <dd className="col-span-2">
                          <details>
                            <summary className="cursor-pointer text-muted-foreground">
                              Proof details
                            </summary>
                            <p className="mt-1 break-words">{row.detail}</p>
                          </details>
                        </dd>
                      )}
                    </div>
                  ))}
                </dl>
              </section>
            ))}
            <p>
              Checks run on this device. The VM and its software are trusted. Yellow assumptions are
              outside the current proof scope; they are not failed checks.
            </p>
            <Button size="sm" variant="outline" onClick={onRetry} disabled={report.pending}>
              Check again
            </Button>
          </div>
        </PopoverPopup>
      </Popover>
    </div>
  );
}
