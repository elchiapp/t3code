import type { AttestationStatus } from "@t3tools/contracts";

export interface AttestationProvider {
  readonly instanceId: string;
  readonly label: string;
}

interface Row {
  readonly title: string;
  readonly result: string;
  readonly explanation: string;
  readonly detail?: string | undefined;
}

function result(state?: string): string {
  switch (state) {
    case "verified":
      return "Verified";
    case "failed":
      return "Failed";
    case "checking":
      return "Checking";
    case "approval_required":
      return "Approval required";
    default:
      return "Not verified";
  }
}

export function attestationReport(
  status: AttestationStatus,
  canSend: boolean,
  environmentLabel?: string,
  provider?: AttestationProvider,
) {
  let local = false;
  try {
    local = ["127.0.0.1", "localhost", "[::1]"].includes(new URL(status.origin).hostname);
  } catch {}
  const targets = status.targets;
  const covered =
    provider === undefined ||
    targets?.inferenceProviderIds.includes(provider.instanceId) === true ||
    status.checks[`inference:${provider.instanceId}`] !== undefined;
  const directService = !covered
    ? provider?.instanceId === "codex"
      ? "ChatGPT / OpenAI"
      : provider?.instanceId === "claudeAgent"
        ? "Claude / Anthropic"
        : undefined
    : undefined;
  const providerName = provider?.label ?? "Selected inference provider";
  const currentResult = (state?: string) =>
    state === "verified" && status.phase === "expired"
      ? "Expired"
      : state === "verified" && status.phase === "checking"
        ? "Checking"
        : result(state);
  const inferenceState = status.checks.inference?.state;
  const inferenceResult = directService
    ? "TEE attestation not offered"
    : !covered
      ? "TEE attestation not configured"
      : inferenceState === undefined && status.phase === "checking"
        ? "Checking"
        : currentResult(inferenceState);
  const platformPassed =
    status.phase !== "expired" &&
    status.phase !== "checking" &&
    ["environment_connection", "hardware", "tls_key_commitment"].every(
      (key) => status.checks[key]?.state === "verified",
    );
  const row = (key: string, title: string, explanation: string): Row => ({
    title,
    explanation,
    result: currentResult(status.checks[key]?.state),
    detail: status.checks[key]?.detail,
  });
  const platformRows = local
    ? [
        row(
          "environment_connection",
          "Local connection",
          "Agents and tools run on this device. A local connection is not hardware attestation.",
        ),
      ]
    : [
        row(
          "environment_connection",
          "Environment connection",
          "Checks that this connection reaches the paired environment.",
        ),
        row(
          "hardware",
          "VM hardware",
          "Checks the VM hardware signature, fresh challenge and approved launch and firmware policy.",
        ),
        row(
          "tls_key_commitment",
          "Connection key",
          "Checks that the VM hardware proof commits to the key used for this encrypted connection.",
        ),
        row(
          "proxy_workload",
          "VM software",
          "Checks whether the programs running inside this VM have an accepted software measurement.",
        ),
        row(
          "key_custody",
          "Exclusive key custody",
          "Checks whether there is accepted proof that private keys cannot leave the VM.",
        ),
      ];
  const inferenceRows: Row[] = directService
    ? [
        {
          title: "TEE attestation",
          result: inferenceResult,
          explanation:
            "This connection does not offer TEE attestation. This is not a verification failure.",
        },
      ]
    : !covered
      ? [
          {
            title: "TEE attestation",
            result: inferenceResult,
            explanation:
              "No trusted verifier is configured for this provider. This does not establish whether its service uses a TEE.",
          },
        ]
      : [
          row(
            "inference",
            "Inference hardware, keys and release",
            "Independently checks the selected inference endpoint's TEE evidence, encryption keys and approved software release.",
          ),
          ...(local && targets
            ? [
                row(
                  "hardware",
                  "Proxy VM hardware",
                  `This proof describes the inference proxy at ${targets.vmOrigin}, not this local environment.`,
                ),
                row(
                  "tls_key_commitment",
                  "Proxy connection key",
                  "Checks the key commitment for the confidential VM used as an inference proxy.",
                ),
              ]
            : []),
          row(
            "inference_route",
            "Actual request routing",
            "Endpoint verification alone does not prove that the agent sends each prompt to this endpoint.",
          ),
        ];
  const allVerified =
    canSend && [...platformRows, ...inferenceRows].every((item) => item.result === "Verified");
  const platformSummary = local
    ? "Local device. No confidential-VM attestation applies to this environment."
    : platformPassed
      ? "Required VM hardware and connection checks passed. Software and key-custody limits are listed below."
      : "VM hardware or connection verification has not passed. See the individual results below.";
  const contextualLabel = provider
    ? `${local ? "Local device" : platformPassed ? "VM verified" : "VM not verified"} · ${
        directService
          ? `${providerName}: no TEE`
          : !covered
            ? `${providerName}: not configured`
            : inferenceResult === "Verified"
              ? `${providerName} verified`
              : `${providerName}: ${inferenceResult.toLowerCase()}`
      }`
    : undefined;
  const pending = status.phase === "checking";
  const label =
    contextualLabel ??
    (pending
      ? "Verifying connection"
      : allVerified
        ? "Attestation verified"
        : canSend
          ? "Attestation incomplete"
          : status.phase === "expired" || status.phase === "verified"
            ? "Verification expired"
            : status.phase === "unavailable"
              ? "Verification unavailable"
              : "Verification failed");
  return {
    label,
    allVerified,
    pending,
    neutral: status.phase !== "failed" && (Boolean(directService) || !covered),
    sections: [
      {
        title: "Agent environment",
        name: environmentLabel ?? status.origin,
        origin: status.origin,
        summary: platformSummary,
        rows: platformRows,
      },
      {
        title: "Inference endpoint",
        name: directService ?? providerName,
        origin: covered ? targets?.inferenceOrigin : undefined,
        summary: `${providerName} · ${inferenceResult}`,
        route: covered && targets ? `Via inference proxy: ${targets.proxyOrigin}` : undefined,
        rows: inferenceRows,
      },
    ],
  };
}
