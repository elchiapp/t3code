import { useEffect, useRef, useState } from "react";
import type { AttestationVersionReview as VersionReview } from "@t3tools/contracts";
import {
  canReviewAttestationVersions,
  canConfigureAttestationAuthentication,
  configureAttestationAuthentication,
  decideAttestationVersion,
  reviewAttestationVersions,
} from "@t3tools/client-runtime/attestation";
import { Button } from "../ui/button";

function safeLink(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password;
  } catch {
    return false;
  }
}

export function AttestationVersionReview({
  origin,
  onChanged,
}: {
  origin: string;
  onChanged: () => void;
}) {
  const [reviews, setReviews] = useState<ReadonlyArray<VersionReview>>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const mounted = useRef(true);
  const current = useRef<ReadonlyArray<VersionReview>>([]);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- Closing the native approval review must cancel its outstanding authentication and one-use decisions.
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      for (const review of current.current)
        void decideAttestationVersion({ reviewId: review.id, action: "cancel" }).catch(() => {});
    };
  }, []);

  if (!canReviewAttestationVersions()) return null;
  const load = async () => {
    for (const review of current.current)
      void decideAttestationVersion({ reviewId: review.id, action: "cancel" }).catch(() => {});
    const next = await reviewAttestationVersions(origin);
    if (!mounted.current) {
      for (const review of next)
        void decideAttestationVersion({ reviewId: review.id, action: "cancel" }).catch(() => {});
      return;
    }
    current.current = next;
    setReviews(next);
  };
  const inspect = async () => {
    setBusy(true);
    setMessage(null);
    try {
      await load();
    } catch (cause) {
      if (mounted.current)
        setMessage(cause instanceof Error ? cause.message : "Version review is unavailable.");
    } finally {
      if (mounted.current) setBusy(false);
    }
  };
  const decide = async (review: VersionReview, action: "approve" | "revoke") => {
    setBusy(true);
    setMessage(null);
    try {
      const result = await decideAttestationVersion({ reviewId: review.id, action });
      if (!mounted.current) return;
      setMessage(
        result === "cancelled"
          ? "Cancelled. No approval changed."
          : "Decision saved on this device. Checking again.",
      );
      if (result !== "cancelled") onChanged();
      await load();
    } catch (cause) {
      if (mounted.current)
        setMessage(cause instanceof Error ? cause.message : "No approval was saved.");
    } finally {
      if (mounted.current) setBusy(false);
    }
  };
  return (
    <section className="space-y-3 border-t pt-3">
      <h3 className="font-semibold">Approved versions</h3>
      <p>
        Review the exact build before approving it. Device authentication is required. Later builds
        are not approved automatically.
      </p>
      <Button size="sm" variant="outline" disabled={busy} onClick={() => void inspect()}>
        {busy ? "Checking versions…" : "Review versions"}
      </Button>
      {canConfigureAttestationAuthentication() && (
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
                    setMessage(
                      ready
                        ? "System authentication is ready. You can review and approve the exact build."
                        : "Authentication setup cancelled.",
                    );
                },
                (cause: unknown) => {
                  if (mounted.current)
                    setMessage(
                      cause instanceof Error
                        ? cause.message
                        : "System authentication setup failed.",
                    );
                },
              )
              .finally(() => {
                if (mounted.current) setBusy(false);
              });
          }}
        >
          Set up system authentication
        </Button>
      )}
      {message && (
        <p role="status" className="text-muted-foreground">
          {message}
        </p>
      )}
      {reviews.map((review) => (
        <section key={review.id} className="space-y-2 rounded border p-3">
          <h4 className="font-semibold">
            {review.vendor} · {review.title}
          </h4>
          <p>
            Build {review.version} ·{" "}
            {review.approvalState === "approved"
              ? "Approved"
              : review.approvalState === "rejected"
                ? "Evidence failed"
                : review.approvalState === "revoked"
                  ? "Approval revoked"
                  : "Approval required"}
          </p>
          <p>{review.explanation}</p>
          <details>
            <summary className="cursor-pointer">View changes</summary>
            <ul className="mt-2 list-disc space-y-1 pl-4">
              {review.changes.map((change) => (
                <li key={change}>{change}</li>
              ))}
            </ul>
            {review.links
              .filter((link) => link.kind === "changes" && safeLink(link.url))
              .map((link) => (
                <p key={link.url}>
                  <a
                    href={link.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="underline"
                  >
                    {link.label}
                  </a>
                </p>
              ))}
          </details>
          {review.links
            .filter((link) => link.kind === "source" && safeLink(link.url))
            .map((link) => (
              <p key={link.url}>
                <a href={link.url} target="_blank" rel="noopener noreferrer" className="underline">
                  View source · {link.label}
                </a>
              </p>
            ))}
          <p className="text-muted-foreground">{review.sourceAvailability}</p>
          <details>
            <summary className="cursor-pointer">Proof details</summary>
            <p className="mt-2 break-all">Target: {review.targetOrigin}</p>
            <p className="break-all">
              Approved fingerprint: {review.previousFingerprint ?? "None"}
            </p>
            <p className="break-all">Reviewed fingerprint: {review.fingerprint}</p>
            <p className="break-all">Connection or source identity: {review.binding}</p>
            {review.links
              .filter((link) => ["evidence", "vendor"].includes(link.kind) && safeLink(link.url))
              .map((link) => (
                <p key={link.url}>
                  <a
                    href={link.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="underline"
                  >
                    {link.label}
                  </a>
                </p>
              ))}
          </details>
          <p className="text-muted-foreground">
            A signature identifies the publisher. It does not prove that the software changes are
            safe.
          </p>
          <div className="flex flex-wrap gap-2">
            {review.approvalState !== "approved" && (
              <Button
                size="sm"
                variant="outline"
                disabled={busy || !review.eligible}
                onClick={() => void decide(review, "approve")}
              >
                Approve exact build
              </Button>
            )}
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
        </section>
      ))}
    </section>
  );
}
