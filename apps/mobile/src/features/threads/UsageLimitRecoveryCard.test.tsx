import type { EnvironmentThreadShell } from "@t3tools/client-runtime/state/shell";
import { RunId, type EnvironmentId } from "@t3tools/contracts";
import {
  CHATGPT_USAGE_LIMIT_CODE,
  CHATGPT_WORKSPACE_USAGE_LIMIT_CODE,
} from "@t3tools/shared/usageLimits";
import * as Clipboard from "expo-clipboard";
import type { ReactNode } from "react";
import { AsyncResult } from "effect/reactivity";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vite-plus/test";

const test = vi.hoisted(() => ({
  authorize: vi.fn<() => Promise<boolean>>(),
  isCurrent: vi.fn<() => boolean>(),
  start: vi.fn(),
  update: vi.fn(),
  runtime: vi.fn(),
  interaction: vi.fn(),
  runtimeMode: undefined as "approval-required" | "full-access" | undefined,
  interactionMode: undefined as "default" | "plan" | undefined,
  canOperate: true,
  origin: "https://vm.example",
  selection: undefined as { instanceId: string; model: string } | undefined,
}));
function setup() {
  test.authorize.mockReset().mockResolvedValue(true);
  test.isCurrent.mockReset().mockReturnValue(true);
  test.start.mockReset().mockResolvedValue(AsyncResult.success(undefined));
  test.update.mockReset().mockResolvedValue(AsyncResult.success(undefined));
  test.runtime.mockReset().mockResolvedValue(AsyncResult.success(undefined));
  test.interaction.mockReset().mockResolvedValue(AsyncResult.success(undefined));
  test.runtimeMode = undefined;
  test.interactionMode = undefined;
  test.canOperate = true;
  test.origin = "https://vm.example";
  test.selection = undefined;
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  return { [Symbol.dispose]: () => vi.unstubAllGlobals() };
}

type ButtonProps = { label: string; disabled?: boolean; onPress: () => void };

vi.mock("react-native", () => ({
  Linking: { openURL: vi.fn() },
  Pressable: ({ children, disabled, onPress }: ButtonProps & { children: ReactNode }) => (
    <button type="button" disabled={disabled} onClick={onPress}>
      {children}
    </button>
  ),
  View: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));
vi.mock("expo-clipboard", () => ({ setStringAsync: vi.fn() }));
vi.mock("../../components/ProviderIcon", () => ({ ProviderIcon: () => null }));
vi.mock("../../components/ui/AppText", () => ({
  AppText: ({ children }: { children: ReactNode }) => <span>{children}</span>,
}));
vi.mock("../../components/ui/Button", () => ({
  Button: ({ label, disabled, onPress }: ButtonProps) => (
    <button type="button" disabled={disabled} onClick={onPress}>
      {label}
    </button>
  ),
}));
vi.mock("../../state/threads", () => ({
  threadEnvironment: {
    updateMetadata: "metadata",
    startTurn: "start",
    setRuntimeMode: "runtime",
    setInteractionMode: "interaction",
  },
}));
vi.mock("../../state/use-atom-command", () => ({
  useAtomCommand: (command: string) =>
    ({
      start: test.start,
      metadata: test.update,
      runtime: test.runtime,
      interaction: test.interaction,
    })[command],
}));
vi.mock("../../state/session", () => ({ readEnvironmentScope: () => test.canOperate }));
vi.mock("../attestation/useAttestation", () => ({
  useAttestation: () => ({
    status: { origin: test.origin },
    authorize: test.authorize,
    isCurrent: test.isCurrent,
  }),
}));
vi.mock("../../state/use-composer-drafts", () => ({
  useComposerDraftSettings: () => ({
    modelSelection: test.selection,
    runtimeMode: test.runtimeMode,
    interactionMode: test.interactionMode,
  }),
}));
vi.mock("../../lib/commandMetadata", () => ({
  makeQueuedMessageMetadata: () => ({ commandId: "retry-command", messageId: "retry-message" }),
}));

import { UsageLimitRecoveryCard } from "./UsageLimitRecoveryCard";

const DAY_MS = 24 * 60 * 60 * 1000;

function failedThread(
  resetAt: string | null,
  lastErrorCode?: string,
  lastErrorClass = "usage_limit",
): EnvironmentThreadShell {
  return {
    id: "thread-1",
    modelSelection: { instanceId: "tinfoil", model: "fixture" },
    runtimeMode: "approval-required",
    interactionMode: "default",
    updatedAt: new Date(0).toISOString(),
    snoozedUntil: null,
    latestRun: { runId: "run-1", completedAt: new Date(0).toISOString() },
    limitRecovery: null,
    runtime: { status: "failed", lastErrorClass, lastErrorCode, usageLimitResetAt: resetAt },
  } as unknown as EnvironmentThreadShell;
}

function mount(thread = failedThread(null), canRetry = true) {
  const container = document.createElement("div");
  const root = createRoot(container);
  const render = (value: EnvironmentThreadShell, allowed = canRetry) =>
    act(() =>
      root.render(
        <UsageLimitRecoveryCard
          thread={value}
          environmentId={"env-1" as EnvironmentId}
          canRetry={allowed}
        />,
      ),
    );
  render(thread);
  return {
    container,
    render,
    retry: () =>
      [...container.querySelectorAll("button")].find(
        (button) => button.textContent === "Retry now",
      )!,
    [Symbol.dispose]: () => act(() => root.unmount()),
  };
}

describe("UsageLimitRecoveryCard", () => {
  // Older servers report ChatGPT sharing limits as provider errors and may store a reset.
  it.each([
    [CHATGPT_USAGE_LIMIT_CODE, "usage_limit", null, ["Manage usage"]],
    [CHATGPT_WORKSPACE_USAGE_LIMIT_CODE, "usage_limit", null, ["Copy request for admin"]],
    [CHATGPT_USAGE_LIMIT_CODE, "provider_error", null, ["Manage usage"]],
    [
      CHATGPT_USAGE_LIMIT_CODE,
      "usage_limit",
      new Date(DAY_MS).toISOString(),
      ["Manage usage", "Resume at reset", "Snooze until reset"],
    ],
  ])("shows one ChatGPT notice for %s (%s, reset %s)", (code, errorClass, resetAt, actions) => {
    using _setup = setup();
    const container = document.createElement("div");
    const root = createRoot(container);
    using _root = { [Symbol.dispose]: () => act(() => root.unmount()) };
    act(() =>
      root.render(
        <UsageLimitRecoveryCard
          thread={failedThread(resetAt, code, errorClass)}
          environmentId={"env-1" as EnvironmentId}
          canRetry
        />,
      ),
    );
    expect(container.textContent).toContain("ChatGPT usage limit reached");
    expect(container.textContent).not.toContain("did not report a reset time");
    expect([...container.querySelectorAll("button")].map((button) => button.textContent)).toEqual([
      "Retry now",
      ...actions,
    ]);
  });

  it("drops a failed copy's error once a retry copies the request", async () => {
    using _setup = setup();
    vi.mocked(Clipboard.setStringAsync)
      .mockRejectedValueOnce(new Error("denied"))
      .mockResolvedValueOnce(true);
    const container = document.createElement("div");
    const root = createRoot(container);
    using _root = { [Symbol.dispose]: () => act(() => root.unmount()) };
    act(() =>
      root.render(
        <UsageLimitRecoveryCard
          thread={failedThread(null, CHATGPT_WORKSPACE_USAGE_LIMIT_CODE)}
          environmentId={"env-1" as EnvironmentId}
          canRetry
        />,
      ),
    );
    const copy = () =>
      [...container.querySelectorAll("button")]
        .find((button) => button.textContent === "Copy request for admin")!
        .click();
    await act(async () => copy());
    expect(container.textContent).toContain("Could not copy the request");
    await act(async () => copy());
    expect(container.textContent).toContain("Request copied");
    expect(container.textContent).not.toContain("Could not copy the request");
  });

  it("ignores a second copy while the first is still in flight", async () => {
    using _setup = setup();
    const first = Promise.withResolvers<boolean>();
    vi.mocked(Clipboard.setStringAsync).mockReset().mockReturnValueOnce(first.promise);
    const container = document.createElement("div");
    const root = createRoot(container);
    using _root = { [Symbol.dispose]: () => act(() => root.unmount()) };
    act(() =>
      root.render(
        <UsageLimitRecoveryCard
          thread={failedThread(null, CHATGPT_WORKSPACE_USAGE_LIMIT_CODE)}
          environmentId={"env-1" as EnvironmentId}
          canRetry
        />,
      ),
    );
    const copy = () =>
      [...container.querySelectorAll("button")]
        .find((button) => button.textContent === "Copy request for admin")!
        .click();
    act(() => copy());
    act(() => copy());
    expect(Clipboard.setStringAsync).toHaveBeenCalledTimes(1);
    await act(async () => first.resolve(true));
    expect(container.textContent).toContain("Request copied");
  });

  it("disables Snooze once a reset more than 24.8 days away passes", () => {
    using _setup = setup();
    using _timers = { [Symbol.dispose]: () => vi.useRealTimers() };
    vi.useFakeTimers({ now: 0 });
    const container = document.createElement("div");
    const root = createRoot(container);
    using _root = { [Symbol.dispose]: () => act(() => root.unmount()) };
    act(() =>
      root.render(
        <UsageLimitRecoveryCard
          thread={failedThread(new Date(30 * DAY_MS).toISOString())}
          environmentId={"env-1" as EnvironmentId}
          canRetry
        />,
      ),
    );
    const snooze = () =>
      [...container.querySelectorAll("button")].find(
        (button) => button.textContent === "Snooze until reset",
      );
    expect(snooze()?.disabled).toBe(false);

    act(() => vi.advanceTimersByTime(30 * DAY_MS));

    expect(snooze()?.disabled).toBe(true);
  });
  it("manually continues a quota failure without a reset time, authorizes once and preserves the selected model", async () => {
    using _setup = setup();
    let allow!: (value: boolean) => void;
    const authorization = new Promise<boolean>((resolve) => {
      allow = resolve;
    });
    test.authorize.mockReturnValue(authorization);
    test.selection = { instanceId: "another-provider", model: "selected-model" };
    using screen = mount();
    expect(screen.retry()).toBeDefined();
    await act(async () => {
      screen.retry().click();
      screen.retry().click();
    });
    expect(test.authorize).toHaveBeenCalledTimes(1);
    expect(test.start).not.toHaveBeenCalled();
    await act(async () => {
      allow(true);
      await authorization;
    });
    expect(test.start).toHaveBeenCalledTimes(1);
    expect(test.start).toHaveBeenCalledWith({
      environmentId: "env-1",
      input: {
        threadId: "thread-1",
        commandId: "retry-command",
        manualContinuationOfRunId: "run-1",
        modelSelection: test.selection,
        message: {
          messageId: "retry-message",
          role: "user",
          text: "Continue where you left off.",
          attachments: [],
        },
        runtimeMode: "approval-required",
        interactionMode: "default",
        dispatchMode: "start",
      },
    });
    expect(test.update).not.toHaveBeenCalled();
  });
  it.each(["denied", "expired", "read-only"])(
    "does not dispatch a retry when authorization is %s",
    async (condition) => {
      using _setup = setup();
      test.authorize.mockResolvedValue(condition !== "denied");
      test.isCurrent.mockReturnValue(condition !== "expired");
      test.canOperate = condition !== "read-only";
      using screen = mount();
      await act(async () => screen.retry().click());
      expect(test.start).not.toHaveBeenCalled();
    },
  );
  it.each(["run", "provider", "origin", "permissions"])(
    "discards a retry if its %s changes during authorization",
    async (changed) => {
      using _setup = setup();
      let allow!: (value: boolean) => void;
      const authorization = new Promise<boolean>((resolve) => {
        allow = resolve;
      });
      test.authorize.mockReturnValue(authorization);
      using screen = mount();
      await act(async () => screen.retry().click());
      const prior = failedThread(null);
      const replacement = {
        ...prior,
        latestRun:
          changed === "run" ? { ...prior.latestRun!, runId: RunId.make("run-2") } : prior.latestRun,
      };
      if (changed === "provider") test.selection = { instanceId: "changed", model: "model" };
      if (changed === "origin") test.origin = "https://different-vm.example";
      if (changed === "permissions") test.runtimeMode = "full-access";
      screen.render(replacement);
      await act(async () => {
        allow(true);
        await authorization;
      });
      expect(test.start).not.toHaveBeenCalled();
    },
  );
  it("shows a retry failure and releases the action for another attempt", async () => {
    using _setup = setup();
    test.start.mockResolvedValue(AsyncResult.fail(new Error("Still limited")));
    using screen = mount();
    await act(async () => screen.retry().click());
    expect(screen.container.textContent).toContain("Still limited");
    expect(screen.retry().disabled).toBe(false);
  });
  it("applies the selected permission mode before resuming and stops if it cannot save it", async () => {
    using _setup = setup();
    test.runtimeMode = "approval-required";
    test.interactionMode = "plan";
    using screen = mount({ ...failedThread(null), runtimeMode: "full-access" });
    test.runtime.mockResolvedValueOnce(AsyncResult.fail(new Error("Permission update failed")));
    await act(async () => screen.retry().click());
    expect(test.start).not.toHaveBeenCalled();
    expect(test.interaction).not.toHaveBeenCalled();
    expect(screen.container.textContent).toContain("Permission update failed");
    await act(async () => screen.retry().click());
    expect(test.runtime).toHaveBeenLastCalledWith({
      environmentId: "env-1",
      input: { threadId: "thread-1", runtimeMode: "approval-required" },
    });
    expect(test.interaction).toHaveBeenCalledWith({
      environmentId: "env-1",
      input: { threadId: "thread-1", interactionMode: "plan" },
    });
    expect(test.start).toHaveBeenCalledTimes(1);
    expect(test.start.mock.calls[0]![0].input).toMatchObject({
      runtimeMode: "approval-required",
      interactionMode: "plan",
    });
    expect(test.runtime.mock.invocationCallOrder.at(-1)!).toBeLessThan(
      test.start.mock.invocationCallOrder[0]!,
    );
    expect(test.interaction.mock.invocationCallOrder[0]!).toBeLessThan(
      test.start.mock.invocationCallOrder[0]!,
    );
  });
});
