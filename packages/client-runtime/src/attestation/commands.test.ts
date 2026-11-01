import { describe, expect, it } from "vite-plus/test";
import { ORCHESTRATION_V2_WS_METHODS, WS_METHODS } from "@t3tools/contracts";
import { requiresClientAttestation } from "./commands.ts";

describe("attestation write boundary", () => {
  it.each([
    "message.dispatch",
    "queued-run.edit",
    "queued-run.start",
    "queue.resume",
    "runtime-request.respond",
    "thread.fork",
    "delegated_task.request",
  ])("protects %s", (type) => {
    expect(requiresClientAttestation(ORCHESTRATION_V2_WS_METHODS.dispatchCommand, { type })).toBe(
      true,
    );
  });
  it.each(["thread.stop", "run.interrupt", "subagent.stop", "queued-run.cancel"])(
    "keeps %s available when proof fails",
    (type) => {
      expect(requiresClientAttestation(ORCHESTRATION_V2_WS_METHODS.dispatchCommand, { type })).toBe(
        false,
      );
    },
  );
  it("protects unknown mutations and attachment metadata", () => {
    expect(
      requiresClientAttestation(ORCHESTRATION_V2_WS_METHODS.dispatchCommand, {
        type: "future.write",
      }),
    ).toBe(true);
    expect(requiresClientAttestation(WS_METHODS.attachmentsCreateUploadUrl, {})).toBe(true);
  });
  it("does not block ordinary reads", () => {
    expect(requiresClientAttestation(WS_METHODS.serverGetConfig, {})).toBe(false);
  });
});
