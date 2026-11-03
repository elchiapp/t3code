import { useCallback, useEffect, useRef, useState } from "react";
import { Linking, Pressable, View } from "react-native";
import type { AttestationVersionReview as Review } from "@t3tools/contracts";
import {
  canReviewAttestationVersions,
  decideAttestationVersion,
  reviewAttestationVersions,
  sameReviewedVersion,
} from "@t3tools/client-runtime/attestation";
import { AppText as Text } from "../../components/ui/AppText";
import { Button } from "../../components/ui/Button";
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
export function VersionReview({
  origin,
  onChanged,
  components = allComponents,
  needsApproval = false,
}: {
  origin: string;
  onChanged: () => void;
  components?: ReadonlyArray<Review["component"]>;
  needsApproval?: boolean;
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
  const load = useCallback(async () => {
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
  }, [origin]);
  const inspect = useCallback(async () => {
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
  }, [load]);
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

  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const [manageOpen, setManageOpen] = useState(false);
  if (!available) return null;
  const toggle = (id: string) =>
    setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const details = (review: Review) => (
    <View className="gap-2">
      <Text className="text-sm text-foreground-muted">{review.explanation}</Text>
      {review.changes.map((change) => (
        <Text key={change} className="text-sm">
          • {change}
        </Text>
      ))}
      {review.links
        .filter((link) => safeLink(link.url))
        .map((link) => (
          <Pressable
            key={link.url}
            accessibilityRole="link"
            onPress={() => void Linking.openURL(link.url)}
          >
            <Text className="text-sm font-semibold">{link.label}</Text>
          </Pressable>
        ))}
      <Text className="text-xs text-foreground-muted">{review.sourceAvailability}</Text>
      <Text selectable className="text-xs">
        Target: {review.targetOrigin}
      </Text>
      <Text selectable className="text-xs">
        Previous fingerprint: {review.previousFingerprint ?? "None"}
      </Text>
      <Text selectable className="text-xs">
        This fingerprint: {review.fingerprint}
      </Text>
      <Text selectable className="text-xs">
        Connection or source identity: {review.binding}
      </Text>
      <Text className="text-xs text-foreground-muted">
        Publisher signatures identify the release. They do not guarantee that its changes are safe.
      </Text>
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
  );
  return (
    <View className="gap-3">
      <View className="flex-row items-center justify-between gap-2">
        <Text accessibilityRole="header" className="text-lg font-semibold">
          Updates
        </Text>
        {(errorDetails || pending.some((review) => !review.eligible)) && (
          <Pressable accessibilityRole="button" disabled={busy} onPress={() => void inspect()}>
            <Text className="text-sm font-semibold">{busy ? "Checking…" : "Try again"}</Text>
          </Pressable>
        )}
      </View>
      {message && (
        <Text accessibilityLiveRegion="polite" className="text-sm text-foreground-muted">
          {message}
        </Text>
      )}
      {busy && reviews.length === 0 && (
        <Text accessibilityLiveRegion="polite" className="text-sm">
          Checking update information…
        </Text>
      )}
      {!busy && !message && reviews.length > 0 && pending.length === 0 && (
        <Text className="text-sm">No updates need approval.</Text>
      )}
      {pending.map((review) => (
        <View key={review.id} className="gap-3 rounded-xl border border-border p-3">
          <Text accessibilityRole="header" className="font-semibold">
            {reviewName(review)} {review.eligible ? "update" : "needs attention"}
          </Text>
          <Text className="text-sm font-semibold">{versionChange(review)}</Text>
          <Text className="text-sm">
            {review.eligible
              ? "The identity checks passed. Approve this version to continue."
              : "We couldn't verify this version. Check again or open details."}
          </Text>
          {review.approvalState !== "approved" && (
            <Button
              label="Approve update"
              tone="contrast"
              disabled={busy || !review.eligible}
              onPress={() => void decide(review, "approve")}
            />
          )}
          {review.eligible && (
            <Text className="text-xs text-foreground-muted">
              Your device will ask you to confirm your identity.
            </Text>
          )}
          <Pressable
            accessibilityRole="button"
            accessibilityState={{ expanded: expanded.has(review.id) }}
            onPress={() => toggle(review.id)}
          >
            <Text className="text-sm font-semibold">Update details</Text>
          </Pressable>
          {expanded.has(review.id) && details(review)}
        </View>
      ))}
      {approved.length > 0 && (
        <View className="gap-3">
          <Pressable
            accessibilityRole="button"
            accessibilityState={{ expanded: manageOpen }}
            onPress={() => setManageOpen((value) => !value)}
          >
            <Text className="text-sm font-semibold">
              Manage approved versions ({approved.length})
            </Text>
          </Pressable>
          {manageOpen &&
            approved.map((review) => (
              <View key={review.id} className="gap-2 rounded-xl border border-border p-3">
                <Text className="font-semibold">
                  {reviewName(review)} · {review.version} · Approved
                </Text>
                {details(review)}
              </View>
            ))}
        </View>
      )}
      {errorDetails && (
        <View className="gap-2">
          <Pressable accessibilityRole="button" onPress={() => toggle("error")}>
            <Text className="text-sm font-semibold">Error details</Text>
          </Pressable>
          {expanded.has("error") && (
            <Text className="text-xs text-foreground-muted">{errorDetails}</Text>
          )}
        </View>
      )}
    </View>
  );
}
