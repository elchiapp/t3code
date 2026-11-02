import { useState } from "react";
import { Pressable, ScrollView, View } from "react-native";
import type { AttestationStatus } from "@t3tools/contracts";
import { AppText as Text } from "../../components/ui/AppText";
import { Sheet } from "../../components/ui/Sheet";

const checks = [
  [
    "environment_connection",
    "VM connection",
    "Checks the actual encrypted connection to your paired VM.",
  ],
  [
    "hardware",
    "VM hardware",
    "Checks fresh hardware evidence and the approved VM launch and firmware policy.",
  ],
  [
    "tls_key_commitment",
    "Connection key",
    "Checks that the hardware proof includes the key enforced by this app's connections.",
  ],
  [
    "inference",
    "Inference service",
    "This phone independently checks the configured inference service's hardware evidence, encryption keys and approved release.",
  ],
  [
    "proxy_workload",
    "VM software",
    "The programs running inside the VM are not independently measured.",
  ],
  [
    "key_custody",
    "Exclusive key custody",
    "There is no accepted proof that private keys cannot be copied.",
  ],
  [
    "inference_route",
    "Inference routing",
    "There is no independent proof of where the VM forwards each inference request.",
  ],
] as const;

export function AttestationIndicator({
  status,
  canSend,
  retry,
  overrideAccepted = false,
  revokeOverride,
}: {
  status: AttestationStatus;
  canSend: boolean;
  retry: () => void;
  overrideAccepted?: boolean;
  revokeOverride?: () => void;
}) {
  const [showDetails, setShowDetails] = useState(false);
  const complete = canSend && checks.every(([key]) => status.checks[key]?.state === "verified");
  const label = canSend
    ? complete
      ? "Attestation verified"
      : "Attestation incomplete"
    : status.phase === "checking"
      ? "Verifying connection"
      : status.phase === "failed"
        ? "Verification failed"
        : status.phase === "expired"
          ? "Verification expired"
          : "Verification unavailable";
  return (
    <>
      <Pressable
        accessibilityRole="button"
        accessibilityLabel={label}
        onPress={() => setShowDetails(true)}
        className="px-1 pb-1"
      >
        <Text
          accessibilityLiveRegion="polite"
          className={
            complete
              ? "text-xs text-adaptive-emerald-700-300"
              : canSend || status.phase === "checking"
                ? "text-xs text-warning-foreground"
                : "text-xs text-danger-foreground"
          }
        >
          ● {label}
        </Text>
      </Pressable>
      {showDetails && (
        <Sheet title="Connection verification" onClose={() => setShowDetails(false)}>
          <ScrollView
            className="flex-1"
            nestedScrollEnabled
            contentInsetAdjustmentBehavior="automatic"
            contentContainerStyle={{ padding: 20, paddingBottom: 40, gap: 20 }}
          >
            <View className="gap-2">
              <Text accessibilityRole="header" className="text-lg font-semibold">
                {label}
              </Text>
              <Text className="text-sm text-foreground-muted">
                {canSend
                  ? "Required checks passed. Items marked not verified still depend on trust."
                  : status.message}
              </Text>
            </View>
            {overrideAccepted && (
              <View className="gap-2">
                <Text className="text-sm text-foreground-muted">
                  Unverified sending is allowed for this conversation until you close the app.
                </Text>
                <Pressable
                  accessibilityRole="button"
                  onPress={revokeOverride}
                  className="rounded-xl bg-card-alt px-4 py-3"
                >
                  <Text className="text-center font-semibold">Require verification</Text>
                </Pressable>
              </View>
            )}
            {checks.map(([key, title, explanation]) => (
              <View key={key} className="gap-1">
                <Text className="text-base font-semibold">
                  {title}: {status.checks[key]?.state === "verified" ? "Verified" : "Not verified"}
                </Text>
                <Text className="text-sm text-foreground-muted">{explanation}</Text>
                {key === "inference" && status.checks[key]?.detail && (
                  <Text className="text-sm text-foreground-muted">{status.checks[key].detail}</Text>
                )}
              </View>
            ))}
            <Text className="text-sm text-foreground-muted">
              These checks run on this phone. No laptop is required. Other inference providers do
              not become confidential.
            </Text>
            <Pressable
              accessibilityRole="button"
              onPress={retry}
              className="rounded-xl bg-card-alt px-4 py-3"
            >
              <Text className="text-center font-semibold">Check again</Text>
            </Pressable>
          </ScrollView>
        </Sheet>
      )}
    </>
  );
}
