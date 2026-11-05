// @effect-diagnostics nodeBuiltinImport:off -- Native certificate, device authentication and managed verifier lifecycle boundary.
import {
  AttestationVersionReview,
  DeviceVersionDecisionRecord,
  type AttestationRequest,
  type AttestationStatus,
  type AttestationVersionDecision,
} from "@t3tools/contracts";
import { createDeviceApprovalController } from "@t3tools/client-runtime/attestation";
import * as Context from "effect/Context";
import * as Crypto from "effect/Crypto";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";
import * as Option from "effect/Option";
import * as ByteSize from "effect/ByteSize";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpIncomingMessage from "effect/http/HttpIncomingMessage";
import * as NodeOS from "node:os";
import * as NodeChildProcess from "node:child_process";
import * as NodeUtil from "node:util";
import { createManagedVerifierRuntime, readDevicePolicy } from "./verifierRuntime.ts";
import * as NodeTls from "node:tls";
// @effect-diagnostics-next-line nodeBuiltinImport:off -- Effect Crypto cannot parse an X.509 public key.
import * as NodeCrypto from "node:crypto";
import * as Electron from "electron";
import * as DesktopEnvironment from "../app/DesktopEnvironment.ts";
import {
  createCertificateVerifier,
  createDesktopVerifier,
  decodeDevicePolicy,
} from "./desktopVerifier.ts";
import { createDesktopVersionStore } from "./desktopVersionStore.ts";
import { authenticateDevice, configureLinuxApprovalPolicy } from "./deviceAuthentication.ts";
import * as ElectronWindow from "../electron/ElectronWindow.ts";
import * as Channels from "../ipc/channels.ts";

const reviewSnapshot = Schema.decodeUnknownSync(
  Schema.Struct({
    reviews: Schema.Array(AttestationVersionReview),
    decisions: Schema.Array(DeviceVersionDecisionRecord),
  }),
);
const decisionSnapshot = Schema.decodeUnknownSync(
  Schema.Struct({ decisions: Schema.Array(DeviceVersionDecisionRecord) }),
);

function peerPublicKey(origin: string): Promise<Uint8Array> {
  const target = new URL(origin);
  return new Promise((resolve, reject) => {
    const socket = NodeTls.connect({
      host: target.hostname,
      port: Number(target.port || 443),
      servername: target.hostname,
      rejectUnauthorized: true,
    });
    socket.setTimeout(5_000, () => socket.destroy(new Error("Environment TLS check timed out")));
    socket.once("error", reject);
    socket.once("secureConnect", () => {
      // The legacy public key can be an EC point; the report commits to SPKI.
      const key = socket
        .getPeerX509Certificate()
        ?.publicKey.export({ type: "spki", format: "der" });
      if (key) resolve(key);
      else reject(new Error("Environment public key is unavailable"));
      socket.destroy();
    });
  });
}

export class DesktopAttestation extends Context.Service<
  DesktopAttestation,
  {
    readonly get: (request: AttestationRequest) => Effect.Effect<AttestationStatus>;
    readonly reviewVersions: (
      request: AttestationRequest,
    ) => Effect.Effect<ReadonlyArray<AttestationVersionReview>>;
    readonly decideVersion: (
      request: AttestationVersionDecision,
    ) => Effect.Effect<"approved" | "revoked" | "cancelled">;
    readonly configureAuthentication: Effect.Effect<boolean>;
    readonly installConnectionGate: Effect.Effect<void>;
    readonly shutdown: Effect.Effect<void>;
  }
>()("@t3tools/desktop/attestation/DesktopAttestation") {}

class DeviceVerifierError extends Schema.TaggedError<DeviceVerifierError>()("DeviceVerifierError", {
  message: Schema.String,
}) {}

const make = Effect.gen(function* () {
  const context = yield* Effect.context<never>();
  const runPromise = Effect.runPromiseWith(context);
  const environment = yield* DesktopEnvironment.DesktopEnvironment;
  const crypto = yield* Crypto.Crypto;
  const http = yield* HttpClient.HttpClient;
  const windows = yield* ElectronWindow.ElectronWindow;
  const policyPath = environment.path.join(environment.baseDir, "attestation-client.json");
  const services: Parameters<typeof createDesktopVerifier>[0] = {
    readPolicy: () =>
      readDevicePolicy(
        policyPath,
        environment.isPackaged
          ? environment.path.join(environment.resourcesPath, "attestation-client.json")
          : undefined,
      ),
    readStatus: async (origin: string) => {
      const policy = decodeDevicePolicy(await services.readPolicy());
      await runtime.ensure(origin, policy.modelOrigin);
      return runPromise(
        http.get(origin + "/status").pipe(
          Effect.flatMap((response) =>
            Effect.gen(function* () {
              if (response.status !== 200)
                return yield* new DeviceVerifierError({ message: "Verifier is unavailable" });
              return yield* response.json;
            }),
          ),
          Effect.provideService(HttpIncomingMessage.MaxBodySize, ByteSize.kibibytes(128)),
          Effect.timeout("4 seconds"),
        ),
      );
    },
    refresh: (origin: string) =>
      runPromise(
        http.post(origin + "/refresh").pipe(
          Effect.flatMap((response) =>
            [200, 204, 303].includes(response.status)
              ? Effect.void
              : Effect.fail(new DeviceVerifierError({ message: "Verification refresh failed" })),
          ),
          Effect.timeout("45 seconds"),
        ),
      ),
    peerKey: async (origin: string) => {
      const key = await peerPublicKey(origin);
      return Buffer.from(await runPromise(crypto.digest("SHA-256", key))).toString("hex");
    },
  };
  const runtime = createManagedVerifierRuntime({
    support: environment.path.join(environment.appDataDirectory, "T3 Attested"),
    resources: environment.resourcesPath,
    platform: environment.platform,
    retireLegacy: async () => {
      if (environment.platform !== "darwin") return;
      // Only the installer-owned job is retired; custom verifier services remain untouched.
      await NodeUtil.promisify(NodeChildProcess.execFile)(
        "/bin/launchctl",
        ["bootout", `gui/${NodeOS.userInfo().uid}/io.elchiapp.t3attested.verifier`],
        { timeout: 5000 },
      ).catch(() => {});
    },
  });
  const verify = createDesktopVerifier(services);
  const verifyCertificate = createCertificateVerifier(services);
  const newId = () => runPromise(crypto.randomUUIDv4().pipe(Effect.orDie));
  const store = createDesktopVersionStore(
    environment.path.join(environment.appDataDirectory, "T3 Attested", "attestation-versions.json"),
    newId,
    { platform: environment.platform, uid: NodeOS.userInfo().uid },
  );
  const activeAuthentications = new Map<string, AbortController>();
  const localPolicy = async () => {
    const policy = decodeDevicePolicy(await services.readPolicy());
    const verifier = new URL(policy.verifierOrigin);
    if (
      verifier.protocol !== "http:" ||
      verifier.hostname !== "127.0.0.1" ||
      verifier.pathname !== "/" ||
      verifier.username ||
      verifier.password ||
      verifier.search ||
      verifier.hash ||
      !/^[a-f0-9]{64}$/.test(policy.tlsSpkiSha256 ?? "")
    )
      throw new Error("The trusted device verifier is not configured.");
    await runtime.ensure(verifier.origin, policy.modelOrigin);
    return { ...policy, verifierOrigin: verifier.origin };
  };
  const publicJson = (url: string) =>
    runPromise(
      http.get(url).pipe(
        Effect.flatMap((response) =>
          Effect.gen(function* () {
            if (response.status !== 200)
              return yield* new DeviceVerifierError({ message: "Version review is unavailable." });
            return yield* response.json;
          }),
        ),
        Effect.provideService(HttpIncomingMessage.MaxBodySize, ByteSize.kibibytes(128)),
        Effect.timeout("45 seconds"),
      ),
    );
  const invalidate = () => {
    void runPromise(windows.main).then((window) => {
      if (Option.isSome(window) && !window.value.isDestroyed())
        window.value.webContents.send(Channels.ATTESTATION_VERSIONS_CHANGED_CHANNEL);
    });
  };
  const approvals = createDeviceApprovalController(
    {
      review: async (origin) => {
        const policy = await localPolicy();
        if (!policy.allowedEnvironmentOrigins.includes(origin))
          throw new Error("This environment has no trusted review policy.");
        const snapshot = reviewSnapshot(
          await publicJson(
            policy.verifierOrigin + "/versions/review?origin=" + encodeURIComponent(origin),
          ),
        );
        for (const review of snapshot.reviews) {
          if (
            review.origin !== origin ||
            (review.component === "vm-firmware" &&
              (review.targetOrigin !== policy.modelOrigin ||
                (review.eligible && review.binding !== policy.tlsSpkiSha256))) ||
            (review.component === "inference-release" &&
              review.targetOrigin !== policy.inferenceOrigin)
          )
            throw new Error("The review belongs to another target or connection key.");
        }
        return snapshot.reviews;
      },
      authenticate: async (reason, review) => {
        const window = await runPromise(windows.main);
        if (Option.isNone(window) || window.value.isDestroyed()) return false;
        const signal = new AbortController();
        activeAuthentications.set(review.id, signal);
        const file =
          environment.platform === "win32" ? "t3-attestation-auth.exe" : "t3-attestation-auth";
        const helperPath = environment.isPackaged
          ? environment.path.join(environment.resourcesPath, "attestation-auth", file)
          : environment.path.join(environment.rootDir, ".t3", "attestation-auth", file);
        try {
          return await authenticateDevice(reason, {
            platform: environment.platform,
            helperPath,
            windowHandle: window.value.getNativeWindowHandle(),
            signal: signal.signal,
          });
        } finally {
          activeAuthentications.delete(review.id);
        }
      },
      read: async () => {
        const stored = await store.read();
        if (stored !== null) return stored;
        const policy = await localPolicy();
        return decisionSnapshot(await publicJson(policy.verifierOrigin + "/versions/decisions"))
          .decisions;
      },
      write: store.write,
      invalidate,
    },
    Date.now,
    newId,
  );
  return DesktopAttestation.of({
    shutdown: Effect.sync(() => runtime.stop()),
    installConnectionGate: Effect.sync(() => {
      Electron.app.once("will-quit", () => runtime.stop());
      void services
        .readPolicy()
        .then((raw) => {
          if (raw === null) return;
          const policy = decodeDevicePolicy(raw);
          return runtime.ensure(policy.verifierOrigin, policy.modelOrigin);
        })
        .catch(() => {});
      Electron.session.defaultSession.setCertificateVerifyProc((request, callback) => {
        const check = async () => {
          const key = new NodeCrypto.X509Certificate(request.certificate.data).publicKey.export({
            type: "spki",
            format: "der",
          });
          const digest = Buffer.from(await runPromise(crypto.digest("SHA-256", key))).toString(
            "hex",
          );
          return verifyCertificate(request.hostname, digest, request.errorCode === 0);
        };
        void check().then(callback, () => callback(-2));
      });
    }),
    get: Effect.fn("DesktopAttestation.get")((request: AttestationRequest) =>
      Effect.promise(() => verify(request)),
    ),
    reviewVersions: Effect.fn("DesktopAttestation.reviewVersions")((request: AttestationRequest) =>
      Effect.promise(() => approvals.review(request.origin)),
    ),
    configureAuthentication: Effect.promise(async () => {
      if (environment.platform !== "linux") return false;
      const window = await runPromise(windows.main);
      if (Option.isNone(window) || window.value.isDestroyed()) return false;
      const choice = await Electron.dialog.showMessageBox(window.value, {
        type: "question",
        title: "Set up T3 device authentication",
        buttons: ["Cancel", "Install authentication rule"],
        defaultId: 0,
        cancelId: 0,
        message: "Install the system rule used to authenticate build approvals?",
        detail:
          "Linux will ask for administrator authentication once to install this Polkit rule. Each later approval authenticates your own account. This rule does not give T3 administrator access.",
      });
      if (choice.response !== 1) return false;
      const policyPath = environment.isPackaged
        ? environment.path.join(
            environment.resourcesPath,
            "attestation-auth",
            "io.elchiapp.t3attested.approve-version.policy",
          )
        : environment.path.join(
            environment.rootDir,
            "native",
            "attestation-auth",
            "io.elchiapp.t3attested.approve-version.policy",
          );
      return configureLinuxApprovalPolicy(policyPath);
    }),
    decideVersion: Effect.fn("DesktopAttestation.decideVersion")(
      (request: AttestationVersionDecision) => {
        if (request.action === "cancel") activeAuthentications.get(request.reviewId)?.abort();
        return Effect.promise(() => approvals.decide(request.reviewId, request.action));
      },
    ),
  });
});

export const layer = Layer.effect(DesktopAttestation, make);
