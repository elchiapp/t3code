import { Alert, Pressable, Text } from "react-native";
import type { AttestationStatus } from "@t3tools/contracts";

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
    "Tinfoil",
    "This phone independently checks Tinfoil's hardware evidence, encryption keys and approved release.",
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
}: {
  status: AttestationStatus;
  canSend: boolean;
  retry: () => void;
}) {
  const complete = canSend && checks.every(([key]) => status.checks[key]?.state === "verified");
  const label = canSend
    ? complete
      ? "Attestation verified"
      : "Attestation incomplete"
    : status.phase === "checking"
      ? "Verifying connection"
      : status.phase === "failed"
        ? "Verification failed. Chat disabled."
        : status.phase === "expired"
          ? "Verification expired. Chat disabled."
          : "Verification unavailable. Chat disabled.";
  const details = () =>
    Alert.alert(
      label,
      [
        canSend
          ? "Required checks passed. VM software, key custody and routing remain trusted where marked unverified."
          : status.message,
        ...checks.map(
          ([key, title, explanation]) =>
            `${title}: ${status.checks[key]?.state === "verified" ? "Verified" : "Not verified"}\n${explanation}`,
        ),
        "These checks run on this phone. No laptop is required. Other inference providers do not become confidential.",
      ].join("\n\n"),
      [
        { text: "Close", style: "cancel" },
        { text: "Check again", onPress: retry },
      ],
    );
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={label}
      onPress={details}
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
  );
}
