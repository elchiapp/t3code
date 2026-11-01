import type { AttestationRequest, AttestationStatus } from "@t3tools/contracts";
import * as Context from "effect/Context";
import * as Crypto from "effect/Crypto";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";
import * as Option from "effect/Option";
import * as ByteSize from "effect/ByteSize";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpIncomingMessage from "effect/http/HttpIncomingMessage";
import * as NodeOS from "node:os";
import * as NodeTls from "node:tls";
// @effect-diagnostics-next-line nodeBuiltinImport:off -- Effect Crypto cannot parse an X.509 public key.
import * as NodeCrypto from "node:crypto";
import * as Electron from "electron";
import * as DesktopEnvironment from "../app/DesktopEnvironment.ts";
import { createCertificateVerifier, createDesktopVerifier } from "./desktopVerifier.ts";

const decodePolicyText = Schema.decodeEffect(Schema.fromJsonString(Schema.Unknown));

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
    readonly installConnectionGate: Effect.Effect<void>;
  }
>()("@t3tools/desktop/attestation/DesktopAttestation") {}

class DeviceVerifierError extends Schema.TaggedError<DeviceVerifierError>()("DeviceVerifierError", {
  message: Schema.String,
}) {}

const make = Effect.gen(function* () {
  const context = yield* Effect.context<never>();
  const runPromise = Effect.runPromiseWith(context);
  const environment = yield* DesktopEnvironment.DesktopEnvironment;
  const files = yield* FileSystem.FileSystem;
  const crypto = yield* Crypto.Crypto;
  const http = yield* HttpClient.HttpClient;
  const policyPath = environment.path.join(environment.baseDir, "attestation-client.json");
  const services = {
    readPolicy: () =>
      runPromise(
        Effect.gen(function* () {
          const info = yield* files.stat(policyPath);
          if (
            info.type !== "File" ||
            Option.getOrUndefined(info.uid) !== NodeOS.userInfo().uid ||
            (info.mode & 0o077) !== 0 ||
            info.size > ByteSize.bytes(32_768)
          )
            return yield* new DeviceVerifierError({ message: "Untrusted device policy" });
          return yield* decodePolicyText(yield* files.readFileString(policyPath));
        }),
      ),
    readStatus: (origin: string) =>
      runPromise(
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
      ),
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
  const verify = createDesktopVerifier(services);
  const verifyCertificate = createCertificateVerifier(services);
  return DesktopAttestation.of({
    installConnectionGate: Effect.sync(() => {
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
  });
});

export const layer = Layer.effect(DesktopAttestation, make);
