import "./confirmation";
import { useEffect, useRef, useState } from "react";
import { View } from "react-native";
import { Asset } from "expo-asset";
import { File } from "expo-file-system";
import * as Crypto from "expo-crypto";
import { WebView } from "react-native-webview";
import * as Effect from "effect/Effect";
import { clientAttestation, unavailableAttestation } from "@t3tools/client-runtime/attestation";
import { createMobileDeviceVerifier } from "./deviceVerifier";
import { nativeTransportProtected, readBundledMobilePolicy } from "./native";
import { installVerifierRecovery } from "./hostLifecycle";
import { probeNativeTransport } from "./transportProbe";
import type { AttestationRequest, AttestationStatus } from "@t3tools/contracts";

interface WorkerReply {
  readonly id?: number;
  readonly ready?: boolean;
  readonly ok?: boolean;
  readonly value?: unknown;
  readonly error?: string;
}

export function VerifierHost() {
  const webview = useRef<WebView<object>>(null);
  const [document, setDocument] = useState<{ html: string; id: number } | null>(null);
  const [attempt, setAttempt] = useState(0);
  const documentId = useRef(0);
  const recoveries = useRef(0);
  const verify = useRef<((request: AttestationRequest) => Promise<AttestationStatus>) | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pending = useRef(
    new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }>(),
  );
  const nextId = useRef(0);
  const ready = useRef(false);
  const approvedOrigins = useRef<ReadonlyArray<string>>([]);
  const stop = useRef(() => {});

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- Keeps the native WebView verifier, signed asset and request registry in step with this host's mounted lifecycle.
  useEffect(() => {
    let active = true;
    const currentAttempt = attempt;
    const unavailable = () => {
      ready.current = false;
      clientAttestation.setDeviceVerifier(async (request) =>
        unavailableAttestation(
          request.origin,
          "Phone verification is unavailable. Sending requires confirmation.",
        ),
      );
      for (const operation of pending.current.values())
        operation.reject(new Error("Verifier stopped"));
      pending.current.clear();
    };
    stop.current = unavailable;
    const removeRecovery = installVerifierRecovery(() => {
      if (ready.current) return false;
      recoveries.current = 0;
      setError(null);
      setAttempt((value) => value + 1);
      return true;
    });
    unavailable();
    const initialize = async () => {
      const policy = readBundledMobilePolicy();
      approvedOrigins.current = policy.environmentOrigins;
      void probeNativeTransport(policy);
      const asset = Asset.fromModule(require("../../../.attestation-build/verifier.html"));
      await asset.downloadAsync();
      if (!asset.localUri) throw new Error("The bundled verifier is missing.");
      const text = await new File(asset.localUri).text();
      const digest = await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, text);
      if (digest !== policy.verifierSha256)
        throw new Error("The bundled verifier does not match the signed policy.");
      if (!active) return;
      const call = (method: string, input?: unknown): Promise<unknown> => {
        if (!ready.current || !webview.current)
          return Promise.reject(new Error("Verifier is not ready"));
        const id = ++nextId.current;
        const operation = new Promise<unknown>((resolve, reject) => {
          pending.current.set(id, { resolve, reject });
          webview.current?.injectJavaScript(
            `void window.T3MobileVerifier.dispatch(${JSON.stringify({ id, method, input })}); true;`,
          );
        });
        return Effect.runPromise(
          Effect.promise(() => operation).pipe(Effect.timeout("40 seconds")),
        ).finally(() => pending.current.delete(id));
      };
      const deviceVerify = createMobileDeviceVerifier({
        policy,
        transportProtected: async () => active && ready.current && nativeTransportProtected(),
        prepare: async () =>
          (await call("prepare")) as {
            nonce: string;
            challenge: Readonly<Record<string, unknown>>;
            expiresAt: number;
          },
        collect: async (input) => {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 25000);
          try {
            const result = await fetch(policy.proofOrigin + "/proof", {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(input),
              redirect: "error",
              signal: controller.signal,
            });
            if (!result.ok) throw new Error("VM hardware proof is unavailable");
            const length = Number(result.headers.get("content-length"));
            if (Number.isFinite(length) && length > 524288)
              throw new Error("Evidence exceeds the size limit");
            const value = await result.text();
            if (value.length > 524288) throw new Error("Evidence exceeds the size limit");
            return JSON.parse(value);
          } finally {
            clearTimeout(timer);
          }
        },
        verifyHardware: async (challenge, evidence) => {
          await call("hardware", { challenge, evidence });
        },
        verifyInference: async () => (await call("inference")) as { state: string; detail: string },
      });
      verify.current = deviceVerify;
      setDocument({ html: text, id: ++documentId.current + currentAttempt });
    };
    void initialize().catch((cause) => {
      if (active) {
        unavailable();
        setError(String(cause));
        if (__DEV__)
          console.warn("Phone verifier initialization failed:", String(cause).slice(0, 240));
      }
    });
    return () => {
      active = false;
      removeRecovery();
      unavailable();
    };
  }, [attempt]);

  const onMessage = (text: string) => {
    if (text.length > 524_288) return;
    let message: WorkerReply;
    try {
      message = JSON.parse(text);
    } catch {
      return;
    }
    if (message.ready) {
      if (!verify.current) return;
      ready.current = true;
      clientAttestation.setDeviceVerifier(verify.current);
      for (const origin of approvedOrigins.current) {
        void clientAttestation.refresh(origin, false).then((status) => {
          if (__DEV__)
            console.info(
              "Phone verifier result:",
              JSON.stringify({
                phase: status.phase,
                message: status.message,
                checks: Object.fromEntries(
                  Object.entries(status.checks).map(([key, value]) => [key, value.state]),
                ),
              }),
            );
        });
      }
      return;
    }
    if (message.id === undefined) return;
    const operation = pending.current.get(message.id);
    if (!operation) return;
    pending.current.delete(message.id);
    if (message.ok) operation.resolve(message.value);
    else
      operation.reject(
        new Error(
          typeof message.error === "string"
            ? message.error.slice(0, 240)
            : "Device proof verification failed",
        ),
      );
  };

  const recover = (message: string) => {
    stop.current();
    if (recoveries.current < 2) {
      recoveries.current++;
      setAttempt((value) => value + 1);
    } else setError(message);
  };

  if (!document || error) return null;
  return (
    <View
      pointerEvents="none"
      accessibilityElementsHidden
      importantForAccessibility="no-hide-descendants"
      style={{ position: "absolute", width: 1, height: 1, opacity: 0 }}
    >
      <WebView<object>
        key={document.id}
        ref={webview}
        source={{ html: document.html, baseUrl: "https://t3-attestation.invalid/" }}
        originWhitelist={["https://t3-attestation.invalid", "about:blank"]}
        onShouldStartLoadWithRequest={(request) =>
          request.url === "about:blank" || request.url === "https://t3-attestation.invalid/"
        }
        onMessage={(event) => onMessage(event.nativeEvent.data)}
        onError={() => recover("Verifier failed")}
        onContentProcessDidTerminate={() => recover("Verifier stopped")}
        onRenderProcessGone={() => recover("Verifier stopped")}
        javaScriptEnabled
        incognito
        thirdPartyCookiesEnabled={false}
        domStorageEnabled={false}
        allowFileAccess={false}
        allowUniversalAccessFromFileURLs={false}
        mixedContentMode="never"
        cacheEnabled={false}
      />
    </View>
  );
}
