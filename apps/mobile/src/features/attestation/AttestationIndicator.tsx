import { useState } from "react";
import { Pressable, ScrollView, View } from "react-native";
import type { AttestationStatus } from "@t3tools/contracts";
import { attestationReport, type AttestationProvider } from "@t3tools/client-runtime/attestation";
import { AppText as Text } from "../../components/ui/AppText";
import { Sheet } from "../../components/ui/Sheet";

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
  const report = attestationReport(status, canSend, environmentLabel, provider);
  return (
    <>
      <Pressable
        accessibilityRole="button"
        accessibilityLabel={report.label}
        onPress={() => setShowDetails(true)}
        className="px-1 pb-1"
      >
        <Text
          accessibilityLiveRegion="polite"
          className={
            report.allVerified
              ? "text-xs text-adaptive-emerald-700-300"
              : report.neutral
                ? "text-xs text-foreground-muted"
                : canSend || report.pending
                  ? "text-xs text-warning-foreground"
                  : "text-xs text-danger-foreground"
          }
        >
          ● {report.label}
        </Text>
      </Pressable>
      {showDetails && (
        <Sheet title="Attestation" onClose={() => setShowDetails(false)}>
          <ScrollView
            className="flex-1"
            nestedScrollEnabled
            contentInsetAdjustmentBehavior="automatic"
            contentContainerStyle={{ padding: 20, paddingBottom: 40, gap: 24 }}
          >
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
              Checks run on this device. The VM and its software are trusted. Yellow assumptions are
              outside the current proof scope; they are not failed checks.
            </Text>
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
