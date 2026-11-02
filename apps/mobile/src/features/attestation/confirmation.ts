import { Alert } from "react-native";
import { clientAttestation } from "@t3tools/client-runtime/attestation";

clientAttestation.setOverrideConfirmation(
  ({ origin }) =>
    new Promise<boolean>((resolve) => {
      Alert.alert(
        "Verification did not pass",
        `Some required attestation checks did not pass: ${origin}\n\nSend anyway? Your approval applies only to this conversation until you close the app.`,
        [
          { text: "Cancel", style: "cancel", onPress: () => resolve(false) },
          { text: "Send anyway", onPress: () => resolve(true) },
        ],
        { cancelable: true, onDismiss: () => resolve(false) },
      );
    }),
);
