import { Alert } from "react-native";
import { clientAttestation } from "@t3tools/client-runtime/attestation";

clientAttestation.setOverrideConfirmation(
  ({ origin, status }) =>
    new Promise<boolean>((resolve) => {
      Alert.alert(
        status.checks.inference?.state === "not_offered"
          ? "No inference TEE attestation"
          : "Verification did not pass",
        `${status.message}\n\nEnvironment: ${origin}\n\nSend anyway? Your approval applies only to this conversation until you close the app.`,
        [
          { text: "Cancel", style: "cancel", onPress: () => resolve(false) },
          { text: "Send anyway", onPress: () => resolve(true) },
        ],
        { cancelable: true, onDismiss: () => resolve(false) },
      );
    }),
);
