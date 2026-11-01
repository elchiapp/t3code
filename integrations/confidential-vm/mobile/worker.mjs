/* oxlint-disable unicorn/require-post-message-target-origin -- React Native WebView uses a one-string native bridge. */
import {
  createChallenge,
  expectedReportData,
  verifySnpEvidence,
  validatePolicy,
  checkChallengeShape,
  sha256B64,
} from "../templates/attestation/verifier/verifier-core.mjs.template";
import { createVcekBindingVerifier } from "../templates/attestation/verifier/vcek-bindings.mjs.template";
import { classifyInferenceRelease } from "../templates/attestation/verifier/inference-release-policy.mjs.template";
import { Verifier } from "@tinfoilsh/verifier";
import { CertificateChain } from "@t3-pinned-vcek";
import { X509Certificate } from "@t3-pinned-x509";
import configuration from "@t3-mobile-policy";

const policy = validatePolicy(configuration.proofPolicy);
const bindings = createVcekBindingVerifier({ CertificateChain, X509Certificate });
const encoder = new TextEncoder();
const originalFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = async (url, options = {}) => {
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (options.signal?.aborted) abort();
  else options.signal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(abort, 10000);
  try {
    const response = await originalFetch(url, { ...options, signal: controller.signal });
    if (!response.body) return response;
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 2 * 1024 * 1024) throw Error("Public proof exceeds the size limit");
        chunks.push(value);
      }
    } finally {
      await reader.cancel().catch(() => {});
    }
    const body = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", abort);
  }
};
const operations = {
  async prepare() {
    const { privateKey: _privateKey, ...challenge } = await createChallenge({
      policy,
      origin: policy.evidenceOrigin,
    });
    const nonce = challenge.nonce;
    challenge.nonce = await sha256B64(
      encoder.encode(
        JSON.stringify([
          "t3-proxy-attestation-v1",
          configuration.modelOrigin,
          nonce,
          configuration.tlsSpkiSha256,
        ]),
      ),
    );
    return { nonce, challenge, expiresAt: challenge.expiresAt };
  },
  async hardware({ challenge, evidence }) {
    if (
      evidence?.version !== 1 ||
      evidence.modelOrigin !== configuration.modelOrigin ||
      evidence.tlsSpkiSha256 !== configuration.tlsSpkiSha256
    )
      throw Error("Evidence target differs from the device policy");
    checkChallengeShape(challenge, policy, Date.now());
    await verifySnpEvidence(evidence.snp, {
      policy,
      expectedReportDataBytes: await expectedReportData(challenge),
      now: Date.now(),
      verifyVcekBindings: bindings,
    });
    return true;
  },
  async inference() {
    const verifier = new Verifier({
      serverURL: policy.tinfoil.enclaveOrigin,
      configRepo: policy.tinfoil.configRepo,
    });
    let deadline;
    try {
      await Promise.race([
        verifier.verify(),
        new Promise((_, reject) => {
          deadline = setTimeout(() => reject(Error("Inference verification timed out")), 35000);
        }),
      ]);
    } finally {
      clearTimeout(deadline);
    }
    const decision = classifyInferenceRelease(
      verifier.getVerificationDocument(),
      policy,
      policy.tinfoil.enclaveOrigin,
      configuration.ownerApprovals,
    );
    return {
      state: decision.status === "verified" ? "verified" : "approval_required",
      detail:
        decision.status === "verified"
          ? `This phone verified Tinfoil ${decision.releaseTag} and its attested encryption keys.`
          : `Tinfoil ${decision.releaseTag} requires approval before sending.`,
    };
  },
};

// All executable code is bundled in the signed app. The VM supplies public evidence only.
globalThis.T3MobileVerifier = {
  async dispatch(message) {
    try {
      if (!Number.isSafeInteger(message.id) || !Object.hasOwn(operations, message.method))
        throw Error("Invalid verification operation");
      const value = await operations[message.method](message.input);
      window.ReactNativeWebView.postMessage(JSON.stringify({ id: message.id, ok: true, value }));
    } catch (error) {
      window.ReactNativeWebView.postMessage(
        JSON.stringify({
          id: message.id,
          ok: false,
          error:
            error instanceof Error
              ? error.message.slice(0, 240)
              : "Device cryptographic verification failed",
        }),
      );
    }
  },
};
window.ReactNativeWebView.postMessage(JSON.stringify({ ready: true }));
