import { useEffect, useRef, useState } from "react";
import { Linking, Pressable, View } from "react-native";
import type { AttestationVersionReview } from "@t3tools/contracts";
import {
  canReviewAttestationVersions,
  decideAttestationVersion,
  reviewAttestationVersions,
} from "@t3tools/client-runtime/attestation";
import { AppText as Text } from "../../components/ui/AppText";

function safeLink(value: string) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password;
  } catch {
    return false;
  }
}

export function VersionReview({ origin, onChanged }: { origin: string; onChanged: () => void }) {
  const [reviews, setReviews] = useState<ReadonlyArray<AttestationVersionReview>>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const mounted = useRef(true);
  const current = useRef<ReadonlyArray<AttestationVersionReview>>([]);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- Closing the native review cancels its pending authentication and one-use approval requests.
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
  const decide = async (review: AttestationVersionReview, action: "approve" | "revoke") => {
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
  const toggle = (id: string) =>
    setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  return (
    <View className="gap-3 border-t border-border pt-4">
      <Text accessibilityRole="header" className="text-lg font-semibold">
        Approved versions
      </Text>
      <Text className="text-sm">
        Review the exact build before approving it. Device authentication is required. Later builds
        are not approved automatically.
      </Text>
      <Pressable
        accessibilityRole="button"
        disabled={busy}
        onPress={() => void inspect()}
        className="rounded-xl bg-card-alt px-4 py-3"
      >
        <Text className="text-center font-semibold">
          {busy ? "Checking versions…" : "Review versions"}
        </Text>
      </Pressable>
      {message && (
        <Text accessibilityLiveRegion="polite" className="text-sm text-foreground-muted">
          {message}
        </Text>
      )}
      {reviews.map((review) => (
        <View key={review.id} className="gap-3 rounded-xl border border-border p-3">
          <Text className="font-semibold">
            {review.vendor} · {review.title}
          </Text>
          <Text className="text-sm">
            Build {review.version} ·{" "}
            {review.approvalState === "approved"
              ? "Approved"
              : review.approvalState === "rejected"
                ? "Evidence failed"
                : review.approvalState === "revoked"
                  ? "Approval revoked"
                  : "Approval required"}
          </Text>
          <Text className="text-sm">{review.explanation}</Text>
          <Pressable accessibilityRole="button" onPress={() => toggle(review.id + ":changes")}>
            <Text className="text-sm font-semibold">View changes</Text>
          </Pressable>
          {expanded.has(review.id + ":changes") &&
            review.changes.map((change) => (
              <Text key={change} className="text-sm">
                • {change}
              </Text>
            ))}
          {review.links
            .filter((link) => ["source", "changes"].includes(link.kind) && safeLink(link.url))
            .map((link) => (
              <Pressable
                key={link.url}
                accessibilityRole="link"
                onPress={() => void Linking.openURL(link.url)}
              >
                <Text className="text-sm font-semibold">
                  {link.kind === "source" ? "View source · " : ""}
                  {link.label}
                </Text>
              </Pressable>
            ))}
          <Text className="text-sm text-foreground-muted">{review.sourceAvailability}</Text>
          <Pressable accessibilityRole="button" onPress={() => toggle(review.id + ":proof")}>
            <Text className="text-sm font-semibold">Proof details</Text>
          </Pressable>
          {expanded.has(review.id + ":proof") && (
            <View className="gap-2">
              <Text selectable className="text-xs">
                Target: {review.targetOrigin}
              </Text>
              <Text selectable className="text-xs">
                Approved fingerprint: {review.previousFingerprint ?? "None"}
              </Text>
              <Text selectable className="text-xs">
                Reviewed fingerprint: {review.fingerprint}
              </Text>
              <Text selectable className="text-xs">
                Connection or source identity: {review.binding}
              </Text>
              {review.links
                .filter((link) => ["evidence", "vendor"].includes(link.kind) && safeLink(link.url))
                .map((link) => (
                  <Pressable
                    key={link.url}
                    accessibilityRole="link"
                    onPress={() => void Linking.openURL(link.url)}
                  >
                    <Text className="text-sm font-semibold">{link.label}</Text>
                  </Pressable>
                ))}
            </View>
          )}
          <Text className="text-xs text-foreground-muted">
            A signature identifies the publisher. It does not prove that the software changes are
            safe.
          </Text>
          {review.approvalState !== "approved" && (
            <Pressable
              accessibilityRole="button"
              disabled={busy || !review.eligible}
              onPress={() => void decide(review, "approve")}
              className="rounded-xl bg-card-alt px-4 py-3"
            >
              <Text className="text-center font-semibold">Approve exact build</Text>
            </Pressable>
          )}
          {review.approvalState === "approved" && (
            <Pressable
              accessibilityRole="button"
              disabled={busy}
              onPress={() => void decide(review, "revoke")}
              className="rounded-xl bg-card-alt px-4 py-3"
            >
              <Text className="text-center font-semibold">Revoke approval</Text>
            </Pressable>
          )}
        </View>
      ))}
    </View>
  );
}
