import { useEffect, useRef, useState } from "react";
import type { AttestationVersionReview as Review } from "@t3tools/contracts";
import {
  canReviewAttestationVersions,
  canConfigureAttestationAuthentication,
  configureAttestationAuthentication,
  decideAttestationVersion,
  reviewAttestationVersions,
  sameReviewedVersion,
} from "@t3tools/client-runtime/attestation";
import { Button } from "../ui/button";
function reviewNeedsRefresh(expiresAt: number): boolean {
  return expiresAt <= Date.now() + 5_000;
}
function safeLink(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password;
  } catch {
    return false;
  }
}
const allComponents: ReadonlyArray<Review["component"]> = ["vm-firmware", "inference-release"];
function reviewName(review: Review) {
  return review.component === "vm-firmware" ? "Private server" : review.vendor;
}
function versionChange(review: Review) {
  return review.previousVersion && review.previousVersion !== review.version
    ? `${review.previousVersion} → ${review.version}`
    : `Version ${review.version}`;
}
export function AttestationVersionReview({
  origin,
  onChanged,
  components = allComponents,
  needsApproval = false,
  management = false,
}: {
  origin: string;
  onChanged: () => void;
  components?: ReadonlyArray<Review["component"]>;
  needsApproval?: boolean;
  management?: boolean;
}) {
  const [reviews, setReviews] = useState<ReadonlyArray<Review>>([]);
  const [busy, setBusy] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorDetails, setErrorDetails] = useState<string | null>(null);
  const mounted = useRef(true);
  const current = useRef<ReadonlyArray<Review>>([]);
  const generation = useRef(0);
  const inspected = useRef(false);
  const previousApproval = useRef(false);
  const available = canReviewAttestationVersions();
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- Closing the review cancels native authentication and invalidates any in-flight proof lookup.
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      inspected.current = false;
      generation.current++;
      for (const review of current.current)
        void decideAttestationVersion({ reviewId: review.id, action: "cancel" }).catch(() => {});
    };
  }, []);
  const load = async () => {
    const request = ++generation.current;
    for (const review of current.current)
      void decideAttestationVersion({ reviewId: review.id, action: "cancel" }).catch(() => {});
    current.current = [];
    const next = await reviewAttestationVersions(origin);
    if (!mounted.current || request !== generation.current) {
      for (const review of next)
        void decideAttestationVersion({ reviewId: review.id, action: "cancel" }).catch(() => {});
      return;
    }
    current.current = next;
    setReviews(next);
    return next;
  };
  const inspect = async () => {
    setBusy(true);
    setMessage(null);
    setErrorDetails(null);
    try {
      await load();
    } catch (cause) {
      if (mounted.current) {
        setMessage("Couldn't check the update. Try again.");
        setErrorDetails(cause instanceof Error ? cause.message : "Version review is unavailable.");
      }
    }
    if (mounted.current) setBusy(false);
  };
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- Opening this panel or discovering a new pending update loads fresh native review metadata without another user click.
  useEffect(() => {
    if (!available) return;
    const shouldInspect = !inspected.current || (needsApproval && !previousApproval.current);
    inspected.current = true;
    previousApproval.current = needsApproval;
    if (shouldInspect) void inspect();
  }, [available, inspect, needsApproval]);
  const decide = async (review: Review, action: "approve" | "revoke") => {
    setBusy(true);
    setMessage(null);
    setErrorDetails(null);
    await (async () => {
      try {
        let selected = review;
        if (reviewNeedsRefresh(review.expiresAt)) {
          const fresh = await load();
          if (!mounted.current) return;
          if (!fresh) return;
          const next = fresh.find((item) => item.component === review.component);
          if (!next) {
            setMessage("This update changed. Review the new version below.");
            return;
          }
          if (!sameReviewedVersion(review, next)) {
            setMessage("This update changed. Review the new version below.");
            return;
          }
          selected = next;
        }
        const result = await decideAttestationVersion({ reviewId: selected.id, action });
        if (!mounted.current) return;
        if (result === "cancelled") setMessage("Cancelled.");
        else setMessage("Saved. Checking your connection…");
        if (result !== "cancelled") onChanged();
        await load();
      } catch (cause) {
        if (mounted.current) {
          setMessage("Your approval wasn't saved. Try again or open details.");
          setErrorDetails(cause instanceof Error ? cause.message : "Approval is unavailable.");
          await load().catch(() => {});
        }
      }
    })().finally(() => {
      if (mounted.current) setBusy(false);
    });
  };
  const visible = reviews.filter((review) => components.includes(review.component));
  const pending = visible.filter(
    (review) => review.approvalState !== "approved" || !review.eligible,
  );
  const approved = visible.filter(
    (review) => review.approvalState === "approved" && review.eligible,
  );

  if (!available) return null;
  const details = (review: Review) => (
    <div className="mt-2 space-y-2 text-muted-foreground">
      <p>{review.explanation}</p>
      <ul className="list-disc space-y-1 pl-4">
        {review.changes.map((change) => (
          <li key={change}>{change}</li>
        ))}
      </ul>
      {review.links
        .filter((link) => safeLink(link.url))
        .map((link) => (
          <p key={link.url}>
            <a href={link.url} target="_blank" rel="noopener noreferrer" className="underline">
              {link.label}
            </a>
          </p>
        ))}
      <p>{review.sourceAvailability}</p>
      <p className="break-all">Target: {review.targetOrigin}</p>
      <p className="break-all">Previous fingerprint: {review.previousFingerprint ?? "None"}</p>
      <p className="break-all">This fingerprint: {review.fingerprint}</p>
      <p className="break-all">Connection or source identity: {review.binding}</p>
      <p>
        Publisher signatures identify the release. They do not guarantee that its changes are safe.
      </p>
      {review.approvalState === "approved" && (
        <Button
          size="sm"
          variant="outline"
          disabled={busy}
          onClick={() => void decide(review, "revoke")}
        >
          Revoke approval
        </Button>
      )}
    </div>
  );
  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <h3 className="font-semibold">{management ? "Saved approvals" : "Updates"}</h3>
        {(errorDetails || pending.some((review) => !review.eligible)) && (
          <Button size="sm" variant="ghost" disabled={busy} onClick={() => void inspect()}>
            {busy ? "Checking…" : "Try again"}
          </Button>
        )}
      </div>
      {message && (
        <p role="status" className="text-muted-foreground">
          {message}
        </p>
      )}
      {busy && reviews.length === 0 && <p role="status">Checking update information…</p>}
      {!management && !busy && !message && reviews.length > 0 && pending.length === 0 && (
        <p>No updates need approval.</p>
      )}
      {pending.map((review) => (
        <section key={review.id} className="space-y-2 rounded border p-3">
          <h4 className="font-semibold">
            {reviewName(review)} {review.eligible ? "update" : "needs attention"}
          </h4>
          <p className="font-medium">{versionChange(review)}</p>
          <p>
            {review.eligible
              ? "The identity checks passed. Approve this version to continue."
              : "We couldn't verify this version. Check again or open details."}
          </p>
          {review.approvalState !== "approved" && (
            <Button
              size="sm"
              disabled={busy || !review.eligible}
              onClick={() => void decide(review, "approve")}
            >
              Approve update
            </Button>
          )}
          {review.eligible && (
            <p className="text-muted-foreground">
              Your device will ask you to confirm your identity.
            </p>
          )}
          <details>
            <summary className="cursor-pointer">Update details</summary>
            {details(review)}
          </details>
        </section>
      ))}
      {approved.length > 0 && (
        <div className="space-y-2">
          {approved.map((review) => (
            <details key={review.id} className="rounded border p-3">
              <summary className="cursor-pointer font-medium">
                {reviewName(review)} · {review.version} · Approved
              </summary>
              {details(review)}
            </details>
          ))}
        </div>
      )}
      {errorDetails && (
        <details>
          <summary className="cursor-pointer">Error details</summary>
          <p className="mt-2 break-words">{errorDetails}</p>
        </details>
      )}
      {canConfigureAttestationAuthentication() && (
        <details>
          <summary className="cursor-pointer">Device approval setup</summary>
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() => {
              setBusy(true);
              void configureAttestationAuthentication()
                .then(
                  (ready) => {
                    if (mounted.current)
                      setMessage(ready ? "Device approval is ready." : "Setup cancelled.");
                  },
                  () => {
                    if (mounted.current) setMessage("Couldn't set up device approval.");
                  },
                )
                .finally(() => {
                  if (mounted.current) setBusy(false);
                });
            }}
          >
            Enable approval on this device
          </Button>
        </details>
      )}
    </section>
  );
}
