import { Button } from "../../components/ui/Button";
import { squashAtomCommandFailure } from "@t3tools/client-runtime/state/runtime";
import { AsyncResult } from "effect/reactivity";
import type { EnvironmentThreadShell } from "@t3tools/client-runtime/state/shell";
import type { EnvironmentId } from "@t3tools/contracts";
import * as DateTime from "effect/DateTime";
import { useLayoutEffect, useRef, useState } from "react";
import { AuthOrchestrationOperateScope, CommandId, MessageId } from "@t3tools/contracts";
import { readEnvironmentScope } from "../../state/session";
import { useAttestation } from "../attestation/useAttestation";
import { scopedThreadKey } from "../../lib/scopedEntities";
import { useComposerDraftSettings } from "../../state/use-composer-drafts";
import { makeQueuedMessageMetadata } from "../../lib/commandMetadata";
import { View } from "react-native";
import { AppText as Text } from "../../components/ui/AppText";
import { useDeadlinePassed } from "../../lib/clock";
import { threadEnvironment } from "../../state/threads";
import { useAtomCommand } from "../../state/use-atom-command";

function retryErrorMessage(cause: unknown): string {
  return cause instanceof Error ? cause.message : "Could not retry this thread.";
}

export function UsageLimitRecoveryCard({
  thread,
  environmentId,
  canRetry,
}: {
  thread: EnvironmentThreadShell;
  environmentId: EnvironmentId;
  canRetry: boolean;
}) {
  const updateMetadata = useAtomCommand(threadEnvironment.updateMetadata);
  const startTurn = useAtomCommand(threadEnvironment.startTurn, { reportFailure: false });
  const draft = useComposerDraftSettings(scopedThreadKey(environmentId, thread.id));
  const selection = draft.modelSelection ?? thread.modelSelection;
  const attestation = useAttestation(environmentId, thread.id, selection.instanceId);

  const retrying = useRef(false);
  const retryScope = useRef<{ context: string; controller: AbortController } | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const resetAt = thread.runtime?.usageLimitResetAt ?? null;
  const canSchedule =
    resetAt !== null &&
    Date.parse(resetAt) > Date.parse(thread.latestRun?.completedAt ?? thread.updatedAt);
  const resetPassed = useDeadlinePassed(resetAt === null ? null : Date.parse(resetAt));
  const runId = thread.latestRun?.runId;
  const retryContext = JSON.stringify([
    environmentId,
    thread.id,
    runId,
    canRetry,
    selection,
    attestation.status.origin,
  ]);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- A committed run, permission, model or connection change must cancel a retry waiting for device authorization.
  useLayoutEffect(() => {
    const scope = { context: retryContext, controller: new AbortController() };
    retryScope.current = scope;
    return () => {
      scope.controller.abort();
      if (retryScope.current === scope) retryScope.current = null;
    };
  }, [retryContext]);
  const recovery = thread.limitRecovery;
  const scheduled =
    recovery?.runId === runId && recovery?.resetAt === resetAt && recovery?.autoResume;
  if (
    thread.runtime?.status !== "failed" ||
    thread.runtime.lastErrorClass !== "usage_limit" ||
    !runId
  )
    return null;
  const snoozed =
    recovery?.snooze === true &&
    recovery.runId === runId &&
    recovery.resetAt === resetAt &&
    resetAt !== null &&
    thread.snoozedUntil !== null &&
    Date.parse(thread.snoozedUntil) === Date.parse(resetAt);
  async function retryNow() {
    const scope = retryScope.current;
    if (
      !canRetry ||
      pending ||
      retrying.current ||
      !scope ||
      scope.controller.signal.aborted ||
      !runId
    )
      return;
    if (!readEnvironmentScope(environmentId, AuthOrchestrationOperateScope)) return;
    retrying.current = true;
    setPending(true);
    setError(null);
    await (async () => {
      try {
        if (!(await attestation.authorize())) return;
        if (scope.controller.signal.aborted) return;
        if (!attestation.isCurrent()) return;
        if (!readEnvironmentScope(environmentId, AuthOrchestrationOperateScope)) return;
        const metadata = makeQueuedMessageMetadata();
        const result = await startTurn({
          environmentId,
          input: {
            threadId: thread.id,
            commandId: CommandId.make(metadata.commandId),
            manualContinuationOfRunId: runId,
            modelSelection: selection,
            message: {
              messageId: MessageId.make(metadata.messageId),
              role: "user",
              text: "Continue where you left off.",
              attachments: [],
            },
            runtimeMode: thread.runtimeMode,
            interactionMode: thread.interactionMode,
            dispatchMode: "start",
          },
        });
        if (AsyncResult.isFailure(result)) {
          if (!scope.controller.signal.aborted)
            setError(retryErrorMessage(squashAtomCommandFailure(result)));
        }
      } catch (cause) {
        if (!scope.controller.signal.aborted) setError(retryErrorMessage(cause));
      }
    })().finally(() => {
      retrying.current = false;
      if (retryScope.current !== null) setPending(false);
    });
  }
  async function toggle(action: "resume" | "snooze") {
    if (!resetAt || !runId || !canSchedule) return;
    if (action === "snooze" && !snoozed && Date.parse(resetAt) <= Date.now()) {
      setError("The reset time has passed. Retry the thread manually.");
      return;
    }
    setPending(true);
    setError(null);
    const result = await updateMetadata({
      environmentId,
      input: {
        threadId: thread.id,
        limitRecovery: {
          runId,
          resetAt,
          ...(action === "resume" ? { autoResume: !scheduled } : { snooze: !snoozed }),
        },
      },
    });
    setPending(false);
    if (AsyncResult.isFailure(result)) {
      const cause = squashAtomCommandFailure(result);
      setError(cause instanceof Error ? cause.message : "Could not change limit recovery.");
    }
  }
  return (
    <View className="mx-3 mb-2 gap-2 rounded-xl border border-warning-foreground/25 bg-screen p-3">
      <Text className="text-sm text-warning-foreground">
        {resetAt
          ? `Usage limit resets ${DateTime.toDateUtc(DateTime.makeUnsafe(resetAt)).toLocaleString()}.`
          : "The provider did not report a reset time. Retry manually when your limit is available."}
      </Text>
      <View className="flex-row flex-wrap gap-2">
        <Button
          label="Retry now"
          tone="secondary"
          disabled={!canRetry || pending}
          onPress={() => void retryNow()}
        />
      </View>
      {canSchedule ? (
        <View className="flex-row flex-wrap gap-2">
          <Button
            label={scheduled ? "Cancel auto-resume" : "Resume at reset"}
            tone="secondary"
            disabled={pending}
            onPress={() => void toggle("resume")}
          />
          <Button
            label={snoozed ? "Wake now" : "Snooze until reset"}
            tone="secondary"
            disabled={pending || (!snoozed && resetPassed)}
            onPress={() => void toggle("snooze")}
          />
        </View>
      ) : null}
      {error ? (
        <Text accessibilityRole="alert" className="text-sm text-destructive">
          {error}
        </Text>
      ) : null}
    </View>
  );
}
