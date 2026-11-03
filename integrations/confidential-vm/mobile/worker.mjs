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
import { assembleAttestationBundle } from "@tinfoilsh/verifier";
import { verifySigstoreBundle } from "@t3-pinned-sigstore";
import {
  createGoogleFirmwareVerifier,
  googleFirmwareCpuHint,
} from "../templates/attestation/verifier/google-firmware.mjs.template";
import { createFirmwareReviewer } from "../templates/attestation/verifier/firmware-review.mjs.template";
import { createInferenceReviewer } from "../templates/attestation/verifier/inference-review.mjs.template";
import {
  validateVersionDecisions,
  inferenceDecision,
} from "../templates/attestation/verifier/version-decisions.mjs.template";
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
const readDecisions = (values) => validateVersionDecisions({ version: 1, decisions: values ?? [] });
const fromBase64 = (value) => Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
const hex = (bytes) => Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
function firmwareReviewer(metadata) {
  if (!Array.isArray(metadata) || metadata.length > 2)
    throw Error("Public firmware evidence is missing.");
  return createFirmwareReviewer({
    verifySnpEvidence,
    expectedReportData,
    checkChallengeShape,
    verifyVcekBindings: bindings,
    verifyGoogleFirmware: createGoogleFirmwareVerifier({ X509Certificate }),
    googleFirmwareCpuHint,
    loadGoogleEvidence: async (measurement) => {
      const value = metadata.find((item) => item.measurement === measurement);
      if (!value || value.endorsementBase64.length > 180000 || value.rootBase64.length > 12000)
        throw Error("Public firmware evidence is missing or too large.");
      return {
        endorsement: fromBase64(value.endorsementBase64),
        rootCertificate: fromBase64(value.rootBase64),
      };
    },
  });
}
const inferenceReviewer = createInferenceReviewer({
  Verifier,
  assembleAttestationBundle,
  verifySigstoreBundle,
  X509Certificate,
  classifyInferenceRelease,
  inferenceDecision,
  loadProvenance: async (repo, digest) => {
    if (repo !== policy.tinfoil.configRepo || !/^[a-f0-9]{64}$/.test(digest))
      throw Error("Invalid provenance target.");
    const response = await fetch(
      `https://github-proxy.tinfoil.sh/repos/${repo}/attestations/sha256:${digest}`,
    );
    if (!response.ok) throw Error("Published source provenance is unavailable.");
    const value = await response.json();
    if (!value.attestations?.[0]?.bundle)
      throw Error("Published source provenance is unavailable.");
    return value.attestations[0].bundle;
  },
});
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
  async firmwareLookup({ evidence, decisions }) {
    const bytes = fromBase64(evidence?.snp?.reportBase64 ?? "");
    if (bytes.length !== 1184) throw Error("Invalid VM hardware report.");
    const current = hex(bytes.subarray(0x90, 0xc0));
    const selected = readDecisions(decisions).find(
      (value) =>
        value.component === "vm-firmware" &&
        value.targetOrigin === configuration.modelOrigin &&
        value.binding === configuration.tlsSpkiSha256,
    );
    return [
      ...new Set([
        selected?.action === "approve" ? selected.fingerprint : policy.hardware.snp.measurementHex,
        current,
      ]),
    ];
  },
  async hardware({ challenge, evidence, decisions, firmwareEvidence }) {
    const result = await firmwareReviewer(firmwareEvidence)({
      policy,
      challenge,
      evidence,
      modelOrigin: configuration.modelOrigin,
      tlsSpkiSha256: configuration.tlsSpkiSha256,
      origin: configuration.environmentOrigins[0],
      decisions: readDecisions(decisions),
      now: Date.now(),
    });
    if (!result.approved) throw Error("VM firmware requires an exact-build approval in T3.");
    return true;
  },
  async reviewFirmware({ origin, challenge, evidence, decisions, firmwareEvidence }) {
    return (
      await firmwareReviewer(firmwareEvidence)({
        policy,
        challenge,
        evidence,
        modelOrigin: configuration.modelOrigin,
        tlsSpkiSha256: configuration.tlsSpkiSha256,
        origin,
        decisions: readDecisions(decisions),
        now: Date.now(),
      })
    ).review;
  },
  async reviewInference({ origin, decisions }) {
    return (
      await inferenceReviewer({
        policy,
        origin,
        decisions: readDecisions(decisions),
        legacyApprovals: configuration.ownerApprovals,
        now: Date.now(),
      })
    ).review;
  },
  async inference({ decisions } = {}) {
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
    const document = verifier.getVerificationDocument();
    const local = inferenceDecision(readDecisions(decisions), {
      endpoint: policy.tinfoil.enclaveOrigin,
      repo: policy.tinfoil.configRepo,
      tag: document?.releaseTag,
      digest: document?.releaseDigest,
    });
    if (local === "approve") decision.status = "verified";
    if (local === "revoke" || local === "unapproved") decision.status = "release_not_approved";
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
