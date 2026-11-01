import { expect, it } from "@effect/vitest";
import { vi } from "vite-plus/test";
import {
  CommandId,
  EnvironmentId,
  ORCHESTRATION_V2_WS_METHODS,
  ThreadId,
} from "@t3tools/contracts";
import * as Effect from "effect/Effect";
import * as Fiber from "effect/Fiber";
import * as Option from "effect/Option";
import * as Stream from "effect/Stream";
import * as SubscriptionRef from "effect/SubscriptionRef";
import { clientAttestation, unavailableAttestation } from "../attestation/gate.ts";
import {
  PrimaryConnectionTarget,
  type PreparedConnection,
  type SupervisorConnectionState,
} from "../connection/model.ts";
import { EnvironmentSupervisor } from "../connection/supervisor.ts";
import type { RpcSession } from "./session.ts";
import { requestGuarded, RpcPermissionGuard } from "./client.ts";

const tag = ORCHESTRATION_V2_WS_METHODS.dispatchCommand;
const command = {
  type: "queue.resume" as const,
  commandId: CommandId.make("test-command"),
  threadId: ThreadId.make("test-thread"),
};
const fixture = Effect.gen(function* () {
  let sends = 0;
  const target = new PrimaryConnectionTarget({
    environmentId: EnvironmentId.make("test-environment"),
    label: "Test VM",
    httpBaseUrl: "https://vm.example",
    wsBaseUrl: "wss://vm.example",
  });
  const connection: PreparedConnection = {
    environmentId: target.environmentId,
    label: target.label,
    httpBaseUrl: target.httpBaseUrl,
    socketUrl: target.wsBaseUrl,
    httpAuthorization: null,
    target,
  };
  const client = {
    [tag]: () =>
      Effect.sync(() => {
        sends++;
        return {};
      }),
  } as unknown as RpcSession["client"];
  const session: RpcSession = {
    client,
    initialConfig: Effect.die("unused"),
    subscribeServerConfig: () => Stream.empty,
    ready: Effect.void,
    probe: Effect.void,
    closed: Effect.never,
  };
  const supervisor: EnvironmentSupervisor["Service"] = {
    target,
    prepared: yield* SubscriptionRef.make(Option.some(connection)),
    session: yield* SubscriptionRef.make(Option.some(session)),
    state: yield* SubscriptionRef.make({} as SupervisorConnectionState),
    connect: Effect.void,
    disconnect: Effect.void,
    retryNow: Effect.void,
  };
  const execute = requestGuarded(tag, command).pipe(
    Effect.provideService(EnvironmentSupervisor, supervisor),
    Effect.provideService(RpcPermissionGuard, { authorize: () => Effect.void }),
  );
  return { supervisor, connection, execute, sends: () => sends };
});

it.effect("does not dispatch when device verification fails", () =>
  Effect.gen(function* () {
    const test = yield* fixture;
    using _verify = vi.spyOn(clientAttestation, "authorizeWithOverride").mockResolvedValue({
      allowed: false,
      requiresOverride: true,
      status: unavailableAttestation("https://vm.example", "Attestation failed"),
    });
    const error = yield* Effect.flip(test.execute);
    expect(error._tag).toBe("EnvironmentRpcUnavailableError");
    expect(error.message).toBe(
      "This environment was not attested. Confirm sending in the composer.",
    );
    expect(test.sends()).toBe(0);
  }),
);

it.effect("does not send on a connection replaced during verification", () =>
  Effect.gen(function* () {
    const test = yield* fixture;
    let markEntered = () => {};
    let release: (
      value: Awaited<ReturnType<typeof clientAttestation.authorizeWithOverride>>,
    ) => void = () => {};
    const entered = new Promise<void>((resolve) => {
      markEntered = resolve;
    });
    const allowed = new Promise<
      Awaited<ReturnType<typeof clientAttestation.authorizeWithOverride>>
    >((resolve) => {
      release = resolve;
    });
    using _verify = vi.spyOn(clientAttestation, "authorizeWithOverride").mockImplementation(() => {
      markEntered();
      return allowed;
    });
    const sending = yield* test.execute.pipe(Effect.forkChild);
    yield* Effect.promise(() => entered);
    yield* SubscriptionRef.set(
      test.supervisor.prepared,
      Option.some({ ...test.connection, httpBaseUrl: "https://other.example" }),
    );
    release({
      allowed: true,
      requiresOverride: false,
      status: unavailableAttestation("https://vm.example"),
    });
    const error = yield* Effect.flip(Fiber.join(sending));
    expect(error._tag).toBe("EnvironmentRpcUnavailableError");
    expect(test.sends()).toBe(0);
  }),
);

it.effect("dispatches once after verification on the unchanged connection", () =>
  Effect.gen(function* () {
    const test = yield* fixture;
    const authorize = vi.spyOn(clientAttestation, "authorizeWithOverride").mockResolvedValue({
      allowed: true,
      requiresOverride: false,
      status: unavailableAttestation("https://vm.example"),
    });
    using _verify = authorize;
    yield* test.execute;
    expect(authorize).toHaveBeenCalledWith("https://vm.example", "test-thread");
    expect(test.sends()).toBe(1);
  }),
);
