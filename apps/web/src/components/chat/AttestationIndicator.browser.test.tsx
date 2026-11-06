import { describe, expect, it, vi } from "vite-plus/test";
import { page } from "vite-plus/test/browser";
import type { AttestationStatus } from "@t3tools/contracts";
import { render } from "../../../test/render";
import { AttestationIndicator } from "./AttestationIndicator";
import { useOriginAttestation } from "../../attestation/useOriginAttestation";
import { clientAttestation } from "@t3tools/client-runtime/attestation";

function SubscribedComposer() {
  const attestation = useOriginAttestation("https://vm.example:8446", "fixture-thread");
  return (
    <>
      <AttestationIndicator
        {...attestation}
        onRetry={attestation.retry}
        onRevokeOverride={attestation.revokeOverride}
      />
      <button disabled={!attestation.canSend}>Send fixture</button>
    </>
  );
}

const state = (phase: AttestationStatus["phase"]): AttestationStatus => ({
  origin: "https://vm.example:8446",
  phase,
  message:
    phase === "verified"
      ? "VM hardware and Tinfoil verified"
      : "Verification is required before sending.",
  verifiedAt: phase === "verified" ? 0 : null,
  expiresAt: phase === "verified" ? 60000 : null,
  checks: {
    environment_connection: { state: "verified" },
    hardware: { state: "verified" },
    tls_key_commitment: { state: "verified" },
    inference: { state: "verified" },
  },
});

describe("attestation status in the composer", () => {
  it("shows incomplete verification and the missing protections when only required checks pass", async () => {
    const partial = {
      ...state("verified"),
      checks: {
        ...state("verified").checks,
        proxy_workload: { state: "not_configured" },
        key_custody: { state: "not_configured" },
        inference_route: { state: "not_configured" },
      },
    };
    await using screen = await render(
      <AttestationIndicator status={partial} canSend onRetry={() => {}} />,
    );
    await screen.getByRole("button", { name: "Attestation incomplete" }).click();
    await page.getByText("Technical details", { exact: true }).click();
    await expect.element(page.getByText("VM software", { exact: true })).toBeVisible();
    await expect.element(page.getByText("Exclusive key custody", { exact: true })).toBeVisible();
    await expect.element(page.getByText("Actual request routing", { exact: true })).toBeVisible();
    await expect
      .element(page.getByText("Trusted assumption", { exact: true }).nth(2))
      .toBeVisible();
    await expect
      .element(
        page.getByText(
          "Required VM hardware and connection checks passed. Software inside this VM is trusted.",
          { exact: true },
        ),
      )
      .toBeVisible();
  });
  it("separates local agents from Tinfoil and updates when the inference provider changes", async () => {
    const local = {
      ...state("verified"),
      origin: "http://127.0.0.1:3773",
      targets: {
        vmOrigin: "https://vm.example:8446",
        proxyOrigin: "https://vm.example:8447",
        inferenceOrigin: "https://inference.example",
        inferenceProviderIds: ["sealed-provider"],
      },
    };
    await using screen = await render(
      <AttestationIndicator
        status={local}
        canSend
        onRetry={() => {}}
        environmentLabel="My MacBook"
        provider={{ instanceId: "sealed-provider", label: "Tinfoil · Verified inference" }}
      />,
    );
    await screen.getByRole("button", { name: /Local device · Tinfoil/ }).click();
    await page.getByText("Technical details", { exact: true }).click();
    await expect.element(page.getByRole("heading", { name: "Agent environment" })).toBeVisible();
    await expect.element(page.getByRole("heading", { name: "Inference endpoint" })).toBeVisible();
    await expect.element(page.getByText("Tinfoil", { exact: true })).toBeVisible();
    await expect.element(page.getByText("My MacBook", { exact: true })).toBeVisible();
    await expect
      .element(page.getByText("https://inference.example", { exact: true }))
      .toBeVisible();
    await expect
      .element(
        page.getByText(
          "Local device. No confidential-VM attestation applies to this environment.",
          { exact: true },
        ),
      )
      .toBeVisible();
    await expect.element(page.getByText("VM hardware", { exact: true })).not.toBeInTheDocument();
    await screen.rerender(
      <AttestationIndicator
        status={{
          ...local,
          phase: "unavailable",
          checks: { ...local.checks, inference: { state: "not_configured" } },
        }}
        canSend={false}
        onRetry={() => {}}
        environmentLabel="My MacBook"
        provider={{ instanceId: "codex", label: "Codex" }}
      />,
    );
    await expect
      .element(page.getByText("TEE attestation not offered", { exact: true }))
      .toBeVisible();
    await expect.element(page.getByText("ChatGPT / OpenAI", { exact: true })).toBeVisible();
    await expect
      .element(
        page.getByText(
          "This connection does not offer TEE attestation. This is not a verification failure.",
          { exact: true },
        ),
      )
      .toBeVisible();
    await expect
      .element(page.getByText("https://inference.example", { exact: true }))
      .not.toBeInTheDocument();
  });
  it("unlocks after the subscribed device receipt changes, and closes again on failure", async () => {
    const listeners = new Set<() => void>();
    const notify = () => listeners.forEach((listener) => listener());
    let overridden = false;
    using _consent = vi
      .spyOn(clientAttestation, "hasOverride")
      .mockImplementation(() => overridden);
    using snapshot = vi.spyOn(clientAttestation, "get").mockReturnValue(state("checking"));
    using _subscribe = vi
      .spyOn(clientAttestation, "subscribe")
      .mockImplementation((_, listener) => {
        listeners.add(listener);
        return () => listeners.delete(listener);
      });
    using _revoke = vi.spyOn(clientAttestation, "revokeOverride").mockImplementation(() => {
      overridden = false;
      snapshot.mockReturnValue(state("failed"));
      notify();
    });
    await using screen = await render(<SubscribedComposer />);
    await expect.element(screen.getByRole("button", { name: "Send fixture" })).toBeDisabled();
    snapshot.mockReturnValue(state("verified"));
    notify();
    await expect
      .element(screen.getByRole("button", { name: "Attestation incomplete" }))
      .toBeVisible();
    await expect.element(screen.getByRole("button", { name: "Send fixture" })).toBeEnabled();
    snapshot.mockReturnValue(state("failed"));
    notify();
    await expect.element(screen.getByRole("button", { name: "Send fixture" })).toBeDisabled();
    overridden = true;
    snapshot.mockReturnValue(state("failed"));
    notify();
    await screen.getByRole("button", { name: /Connection verification failed/ }).click();
    await expect
      .element(
        page.getByText(
          "Unverified sending is allowed for this conversation until you close the app.",
          { exact: true },
        ),
      )
      .toBeVisible();
    await page.getByRole("button", { name: "Require verification", exact: true }).click();
    await expect
      .element(
        page.getByText(
          "Unverified sending is allowed for this conversation until you close the app.",
          { exact: true },
        ),
      )
      .not.toBeInTheDocument();
  });
  it("shows checking, failure and success without replacing the composer", async () => {
    const retry = vi.fn();
    await using screen = await render(
      <AttestationIndicator status={state("checking")} canSend={false} onRetry={retry} />,
    );
    await expect
      .element(screen.getByRole("button", { name: "Verifying connection" }))
      .toBeVisible();
    await screen.rerender(
      <AttestationIndicator status={state("failed")} canSend={false} onRetry={retry} />,
    );
    await expect
      .element(screen.getByRole("button", { name: /Connection verification failed/ }))
      .toBeVisible();
    const complete = {
      ...state("verified"),
      checks: {
        ...state("verified").checks,
        proxy_workload: { state: "verified" },
        key_custody: { state: "verified" },
        inference_route: { state: "verified" },
      },
    };
    await screen.rerender(<AttestationIndicator status={complete} canSend onRetry={retry} />);
    await expect
      .element(screen.getByRole("button", { name: "Attestation verified" }))
      .toBeVisible();
  });
  it("shows the cause before technical details and exposes an explicit retry", async () => {
    const retry = vi.fn();
    const failed = {
      ...state("failed"),
      targets: {
        vmOrigin: "https://vm.example:8446",
        proxyOrigin: "https://vm.example:8447",
        inferenceProviderIds: ["tinfoil"],
      },
      checks: {
        ...state("failed").checks,
        inference: { state: "failed", detail: "Enclave signature mismatch" },
      },
    };
    await using screen = await render(
      <AttestationIndicator
        status={failed}
        canSend={false}
        onRetry={retry}
        provider={{ instanceId: "tinfoil", label: "Tinfoil" }}
      />,
    );
    await screen.getByRole("button", { name: /Tinfoil verification failed/ }).click();
    await expect
      .element(page.getByText("Enclave signature mismatch. Check again.", { exact: true }))
      .toBeVisible();
    await expect.element(page.getByText("VM hardware", { exact: true })).not.toBeVisible();
    await expect
      .element(page.getByText("No updates need approval.", { exact: true }))
      .not.toBeInTheDocument();
    await page.getByRole("button", { name: "Check again", exact: true }).click();
    expect(retry).toHaveBeenCalledOnce();
    await page.getByText("Technical details", { exact: true }).click();
    await expect.element(page.getByText("VM hardware", { exact: true })).toBeVisible();
  });
  it("does not display unavailable or expired verification as a pass", async () => {
    await using screen = await render(
      <AttestationIndicator status={state("unavailable")} canSend={false} onRetry={() => {}} />,
    );
    await expect
      .element(screen.getByRole("button", { name: /Connection verification failed/ }))
      .toBeVisible();
    await screen.rerender(
      <AttestationIndicator status={state("expired")} canSend={false} onRetry={() => {}} />,
    );
    await expect
      .element(screen.getByRole("button", { name: /Verification expired/ }))
      .toBeVisible();
  });
});
