import type { MobileProofPolicy } from "./deviceVerifier";

export async function probeNativeTransport(policy: MobileProofPolicy): Promise<void> {
  if (!__DEV__ || process.env.EXPO_PUBLIC_ATTESTATION_TRANSPORT_TEST !== "1") return;
  const origin = policy.environmentOrigins[0];
  if (!origin) return;
  const result: { http?: string; websocket?: string } = {};
  try {
    const response = await fetch(origin + "/api/auth/session");
    result.http = "HTTP " + response.status;
  } catch (cause) {
    result.http = cause instanceof Error ? cause.message : "Network error";
  }
  result.websocket = await new Promise<string>((resolve) => {
    const socket = new WebSocket(origin.replace(/^https:/, "wss:") + "/ws");
    const finish = (value: string) => {
      clearTimeout(timer);
      socket.close();
      resolve(value);
    };
    const timer = setTimeout(
      () => finish("No unauthenticated upgrade within the test deadline"),
      8_000,
    );
    socket.onopen = () => finish("Unexpected unauthenticated upgrade");
    socket.onerror = (event) =>
      finish(
        "message" in event && typeof event.message === "string"
          ? event.message
          : "WebSocket connection rejected",
      );
  });
  console.info(
    "Native pinned transport probe (no credentials or content):",
    JSON.stringify(result),
  );
}
