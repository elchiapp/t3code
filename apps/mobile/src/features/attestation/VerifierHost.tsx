import "./confirmation";
import { useEffect, useRef, useState } from "react";
import { View } from "react-native";
import { Asset } from "expo-asset";
import { File } from "expo-file-system";
import * as Crypto from "expo-crypto";
import { WebView } from "react-native-webview";
import * as Effect from "effect/Effect";
import {
  clientAttestation,
  unavailableAttestation,
  createDeviceApprovalController,
  registerDeviceVersionOperations,
  createProofCollector,
} from "@t3tools/client-runtime/attestation";
import type { DeviceVersionOperations } from "@t3tools/client-runtime/attestation";
import * as Schema from "effect/Schema";
import { AttestationVersionReview } from "@t3tools/contracts";
import { createMobileDeviceVerifier } from "./deviceVerifier";
import {
  nativeTransportProtected,
  readBundledMobilePolicy,
  authenticateAttestationOwner,
  cancelAttestationAuthentication,
} from "./native";
import { mobileVersionStore } from "./versionStore";
import { googleFirmwareEvidence } from "./firmwareMetadata";
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

const decodeFirmwareTargets = Schema.decodeUnknownSync(Schema.Array(Schema.String));
const decodeVersionReview = Schema.decodeUnknownSync(AttestationVersionReview);
const collectHardwareResponse = createProofCollector();

async function collectProof(proofOrigin: string, input: unknown) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 25000);
  try {
    const result = await collectHardwareResponse(() =>
      fetch(proofOrigin + "/proof", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
        redirect: "error",
        signal: controller.signal,
      }),
    );
    if (!result.ok)
      throw new Error(
        result.status === 429
          ? "The VM hardware collector is busy. Check again."
          : `VM hardware proof request failed (HTTP ${result.status}).`,
      );
    const length = Number(result.headers.get("content-length"));
    if (Number.isFinite(length) && length > 524288)
      throw new Error("Evidence exceeds the size limit");
    const value = await result.text();
    if (value.length > 524288) throw new Error("Evidence exceeds the size limit");
    return JSON.parse(value);
  } finally {
    clearTimeout(timer);
  }
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
  const versionOperations = useRef<DeviceVersionOperations | null>(null);
  const removeVersionOperations = useRef<(() => void) | null>(null);

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- Keeps the native WebView verifier, signed asset and request registry in step with this host's mounted lifecycle.
  useEffect(() => {
    let active = true;
    const currentAttempt = attempt;
    const unavailable = () => {
      removeVersionOperations.current?.();
      removeVersionOperations.current = null;
      cancelAttestationAuthentication();
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
      const firmwareInputs = async (evidence: unknown) => {
        const decisions = await mobileVersionStore.read();
        const measurements = decodeFirmwareTargets(
          await call("firmwareLookup", { evidence, decisions }),
        );
        return { decisions, firmwareEvidence: await googleFirmwareEvidence(measurements) };
      };
      const makeVerifier = () =>
        createMobileDeviceVerifier({
          policy,
          transportProtected: async () => active && ready.current && nativeTransportProtected(),
          prepare: async () =>
            (await call("prepare")) as {
              nonce: string;
              challenge: Readonly<Record<string, unknown>>;
              expiresAt: number;
            },
          collect: (input) => collectProof(policy.proofOrigin, input),
          verifyHardware: async (challenge, evidence) => {
            await call("hardware", { challenge, evidence, ...(await firmwareInputs(evidence)) });
          },
          verifyInference: async () =>
            (await call("inference", { decisions: await mobileVersionStore.read() })) as {
              state: string;
              detail: string;
            },
        });
      const resetVerifier = () => {
        verify.current = makeVerifier();
        if (ready.current) clientAttestation.setDeviceVerifier(verify.current);
      };
      resetVerifier();
      let authenticating: string | undefined;
      const approvals = createDeviceApprovalController(
        {
          review: async (origin) => {
            if (!policy.environmentOrigins.includes(origin))
              throw new Error("This environment has no trusted review policy.");
            const results = await Promise.allSettled([
              (async () => {
                const prepared = (await call("prepare")) as {
                  nonce: string;
                  challenge: Readonly<Record<string, unknown>>;
                };
                const evidence = await collectProof(policy.proofOrigin, {
                  version: 1,
                  modelOrigin: policy.modelOrigin,
                  tlsSpkiSha256: policy.tlsSpkiSha256,
                  nonce: prepared.nonce,
                  challenge: prepared.challenge,
                });
                return decodeVersionReview(
                  await call("reviewFirmware", {
                    origin,
                    challenge: prepared.challenge,
                    evidence,
                    ...(await firmwareInputs(evidence)),
                  }),
                );
              })(),
              (async () =>
                decodeVersionReview(
                  await call("reviewInference", {
                    origin,
                    decisions: await mobileVersionStore.read(),
                  }),
                ))(),
            ]);
            const reviews = results.map((result, index): AttestationVersionReview =>
              result.status === "fulfilled"
                ? result.value
                : {
                    id: "",
                    origin,
                    component: index === 0 ? "vm-firmware" : "inference-release",
                    targetOrigin:
                      index === 0
                        ? policy.modelOrigin
                        : (policy.inferenceOrigin ?? "Not configured"),
                    binding: "",
                    vendor: index === 0 ? "Google" : "Tinfoil",
                    title: index === 0 ? "VM boot firmware (UEFI)" : "Inference release",
                    version: "Unavailable",
                    fingerprint: "",
                    previousVersion: null,
                    previousFingerprint: null,
                    eligible: false,
                    approvalState: "rejected",
                    explanation:
                      "Fresh evidence did not pass: " +
                      String(
                        result.reason instanceof Error
                          ? result.reason.message
                          : "Review unavailable",
                      ).slice(0, 200),
                    changes: [],
                    links: [],
                    sourceAvailability: "Source links require verified evidence.",
                    expiresAt: Date.now() + 60_000,
                  },
            );
            return reviews;
          },
          authenticate: async (reason, review) => {
            authenticating = review.id;
            try {
              return await authenticateAttestationOwner(reason);
            } finally {
              authenticating = undefined;
            }
          },
          read: mobileVersionStore.read,
          write: mobileVersionStore.write,
          invalidate: resetVerifier,
        },
        Date.now,
        () => Crypto.randomUUID(),
      );
      versionOperations.current = {
        review: (origin) => approvals.review(origin),
        decide: (decision) => {
          if (decision.action === "cancel" && authenticating === decision.reviewId)
            cancelAttestationAuthentication();
          return approvals.decide(decision.reviewId, decision.action);
        },
      };
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
      removeVersionOperations.current?.();
      if (versionOperations.current)
        removeVersionOperations.current = registerDeviceVersionOperations(
          versionOperations.current,
        );
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
