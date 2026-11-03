import { useCallback, useState } from "react";
import { useFocusEffect } from "@react-navigation/native";
import { Pressable, ScrollView, View } from "react-native";
import type { AttestationStatus } from "@t3tools/contracts";
import {
  clientAttestation,
  attestationReport,
  type AttestationProvider,
} from "@t3tools/client-runtime/attestation";
import { AppText as Text } from "../../components/ui/AppText";
import { Sheet } from "../../components/ui/Sheet";
import { VersionReview } from "./VersionReview";

export function AttestationIndicator({
  status,
  canSend,
  retry,
  overrideAccepted = false,
  revokeOverride,
  environmentLabel,
  provider,
}: {
  status: AttestationStatus;
  canSend: boolean;
  retry: () => void;
  overrideAccepted?: boolean;
  revokeOverride?: () => void;
  environmentLabel?: string | undefined;
  provider?: AttestationProvider | undefined;
}) {
  const [showDetails, setShowDetails] = useState(false);
  const [proofsExpanded, setProofsExpanded] = useState(false);
  useFocusEffect(
    useCallback(
      () =>
        clientAttestation.onVersionReviewRequired((origin) => {
          if (origin === status.origin) setShowDetails(true);
        }),
      [status.origin],
    ),
  );
  const report = attestationReport(status, canSend, environmentLabel, provider);
  return (
    <>
      <Pressable
        accessibilityRole="button"
        accessibilityLabel={`${report.label}${report.actionLabel ? `. ${report.actionLabel}` : ""}`}
        onPress={() => setShowDetails(true)}
        className="px-1 pb-1"
      >
        <Text
          accessibilityLiveRegion="polite"
          className={
            report.tone === "green"
              ? "text-xs text-adaptive-emerald-700-300"
              : report.tone === "yellow"
                ? "text-xs text-warning-foreground"
                : report.tone === "gray"
                  ? "text-xs text-foreground-muted"
                  : "text-xs text-danger-foreground"
          }
        >
          ● {report.label}
          {report.actionLabel && (
            <Text className="font-semibold underline"> · {report.actionLabel}</Text>
          )}
        </Text>
      </Pressable>
      {showDetails && (
        <Sheet title="Verification" onClose={() => setShowDetails(false)}>
          <ScrollView
            className="flex-1"
            nestedScrollEnabled
            contentInsetAdjustmentBehavior="automatic"
            contentContainerStyle={{ padding: 20, paddingBottom: 40, gap: 24 }}
          >
            <Text accessibilityLiveRegion="polite" className="text-sm">
              {report.summary}
            </Text>
            {report.reviewComponents.length > 0 && (
              <VersionReview
                key={status.targets?.vmOrigin ?? status.origin}
                origin={status.targets?.vmOrigin ?? status.origin}
                onChanged={retry}
                components={report.reviewComponents}
                needsApproval={report.needsApproval}
              />
            )}
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
            <View className="gap-1">
              {report.sections.map((section) => (
                <Text key={section.title} className="text-sm text-foreground-muted">
                  {section.title === "Agent environment" ? "Environment" : "AI service"}:{" "}
                  {section.name}
                </Text>
              ))}
            </View>
            <Pressable
              accessibilityRole="button"
              accessibilityState={{ expanded: proofsExpanded }}
              onPress={() => setProofsExpanded((value) => !value)}
            >
              <Text className="text-sm font-semibold">Verification details</Text>
            </Pressable>
            {proofsExpanded && (
              <View className="gap-4">
                {report.sections.map((section) => (
                  <View key={section.title} className="gap-3 border-b border-border pb-4">
                    <Text accessibilityRole="header" className="text-lg font-semibold">
                      {section.title}
                    </Text>
                    <Text className="text-base font-semibold">{section.name}</Text>
                    {section.origin && section.origin !== section.name && (
                      <Text className="text-sm text-foreground-muted">{section.origin}</Text>
                    )}
                    <Text className="text-sm">{section.summary}</Text>
                    {section.route && (
                      <Text className="text-sm text-foreground-muted">{section.route}</Text>
                    )}
                    {section.rows.map((row) => (
                      <View key={row.title} className="gap-1">
                        <View className="flex-row items-center gap-2">
                          <View
                            accessible={false}
                            className={
                              row.tone === "green"
                                ? "size-1.5 rounded-full bg-adaptive-emerald-700-300"
                                : row.tone === "red"
                                  ? "size-1.5 rounded-full bg-danger-foreground"
                                  : row.tone === "gray"
                                    ? "size-1.5 rounded-full bg-foreground-muted"
                                    : "size-1.5 rounded-full bg-warning-foreground"
                            }
                          />
                          <Text className="flex-1 text-sm font-semibold">
                            {row.title}: {row.result}
                          </Text>
                        </View>
                        <Text className="text-sm text-foreground-muted">{row.explanation}</Text>
                        {row.detail && (
                          <Text className="text-sm text-foreground-muted">{row.detail}</Text>
                        )}
                      </View>
                    ))}
                  </View>
                ))}
                <Text className="text-sm text-foreground-muted">
                  Checks run on this device. The VM and its software are trusted. Yellow assumptions
                  are outside the current proof scope; they are not failed checks.
                </Text>
              </View>
            )}
            <Pressable
              accessibilityRole="button"
              onPress={retry}
              disabled={report.pending}
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
