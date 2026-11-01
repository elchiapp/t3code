import { describe, expect, it, vi } from "vite-plus/test";
import { page } from "vite-plus/test/browser";
import type { AttestationStatus } from "@t3tools/contracts";
import { render } from "../../../test/render";
import { AttestationIndicator } from "./AttestationIndicator";
import { useOriginAttestation } from "../../attestation/useOriginAttestation";
import { clientAttestation } from "@t3tools/client-runtime/attestation";

function SubscribedComposer() {
  const attestation = useOriginAttestation("https://vm.example:8446");
  return (
    <>
      <AttestationIndicator {...attestation} onRetry={attestation.retry} />
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
  verifiedAt: null,
  expiresAt: null,
  checks: {
    environment_connection: { state: "verified" },
    hardware: { state: "verified" },
    tls_key_commitment: { state: "verified" },
    inference: { state: "verified" },
  },
});

describe("attestation status in the composer", () => {
  it("unlocks after the subscribed device receipt changes, and closes again on failure", async () => {
    let notify = () => {};
    using snapshot = vi.spyOn(clientAttestation, "get").mockReturnValue(state("checking"));
    using permission = vi.spyOn(clientAttestation, "canSend").mockReturnValue(false);
    using _subscribe = vi
      .spyOn(clientAttestation, "subscribe")
      .mockImplementation((_, listener) => {
        notify = listener;
        return () => {};
      });
    await using screen = await render(<SubscribedComposer />);
    await expect.element(screen.getByRole("button", { name: "Send fixture" })).toBeDisabled();
    snapshot.mockReturnValue(state("verified"));
    permission.mockReturnValue(true);
    notify();
    await expect
      .element(screen.getByRole("button", { name: "Attestation verified" }))
      .toBeVisible();
    await expect.element(screen.getByRole("button", { name: "Send fixture" })).toBeEnabled();
    snapshot.mockReturnValue(state("failed"));
    permission.mockReturnValue(false);
    notify();
    await expect.element(screen.getByRole("button", { name: "Send fixture" })).toBeDisabled();
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
    await expect.element(screen.getByRole("button", { name: "Verification failed" })).toBeVisible();
    await screen.rerender(
      <AttestationIndicator status={state("verified")} canSend onRetry={retry} />,
    );
    await expect
      .element(screen.getByRole("button", { name: "Attestation verified" }))
      .toBeVisible();
  });
  it("opens the proof details and exposes an explicit retry", async () => {
    const retry = vi.fn();
    await using screen = await render(
      <AttestationIndicator status={state("failed")} canSend={false} onRetry={retry} />,
    );
    await screen.getByRole("button", { name: "Verification failed" }).click();
    await expect.element(page.getByText("VM hardware", { exact: true })).toBeVisible();
    await expect.element(page.getByText("Connection key", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Check again" }).click();
    expect(retry).toHaveBeenCalledOnce();
  });
  it("does not display unavailable or expired verification as a pass", async () => {
    await using screen = await render(
      <AttestationIndicator status={state("unavailable")} canSend={false} onRetry={() => {}} />,
    );
    await expect
      .element(screen.getByRole("button", { name: "Verification unavailable" }))
      .toBeVisible();
    await screen.rerender(
      <AttestationIndicator status={state("expired")} canSend={false} onRetry={() => {}} />,
    );
    await expect
      .element(screen.getByRole("button", { name: "Verification expired" }))
      .toBeVisible();
  });
});
