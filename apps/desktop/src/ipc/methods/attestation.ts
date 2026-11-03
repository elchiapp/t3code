import {
  AttestationRequest,
  AttestationStatus,
  AttestationVersionReview,
  AttestationVersionDecision,
} from "@t3tools/contracts";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import * as Option from "effect/Option";
import * as DesktopAttestation from "../../attestation/DesktopAttestation.ts";
import * as DesktopIpc from "../DesktopIpc.ts";
import * as Channels from "../channels.ts";
import * as ElectronWindow from "../../electron/ElectronWindow.ts";
import * as DesktopEnvironment from "../../app/DesktopEnvironment.ts";
import { getDesktopUrl } from "../../electron/ElectronProtocol.ts";
import { isApprovalSender } from "../../attestation/approvalSender.ts";

class AttestationCallerError extends Schema.TaggedError<AttestationCallerError>()(
  "AttestationCallerError",
  {
    message: Schema.String,
  },
) {}

const trustedCaller = Effect.fn("desktop.ipc.attestation.trustedCaller")(function* (
  event: DesktopIpc.DesktopIpcInvokeEvent | undefined,
) {
  const windows = yield* ElectronWindow.ElectronWindow;
  const environment = yield* DesktopEnvironment.DesktopEnvironment;
  const main = yield* windows.main;
  if (
    Option.isNone(main) ||
    main.value.isDestroyed() ||
    !isApprovalSender(
      event,
      {
        contentsId: main.value.webContents.id,
        frameId: main.value.webContents.mainFrame.frameTreeNodeId,
      },
      getDesktopUrl(environment.isDevelopment),
    )
  )
    return yield* new AttestationCallerError({
      message: "Version decisions are available only in the installed T3 main window.",
    });
});

export const getAttestationStatus = DesktopIpc.makeIpcMethod({
  channel: Channels.GET_ATTESTATION_STATUS_CHANNEL,
  payload: AttestationRequest,
  result: AttestationStatus,
  handler: Effect.fn("desktop.ipc.attestation.get")(function* (request) {
    const verifier = yield* DesktopAttestation.DesktopAttestation;
    return yield* verifier.get(request);
  }),
});

export const getAttestationVersionReviews = DesktopIpc.makeIpcMethod({
  channel: Channels.GET_ATTESTATION_VERSION_REVIEWS_CHANNEL,
  payload: AttestationRequest,
  result: Schema.Array(AttestationVersionReview),
  handler: Effect.fn("desktop.ipc.attestation.review")(function* (request, event) {
    yield* trustedCaller(event);
    const verifier = yield* DesktopAttestation.DesktopAttestation;
    return yield* verifier.reviewVersions(request);
  }),
});

export const decideAttestationVersion = DesktopIpc.makeIpcMethod({
  channel: Channels.DECIDE_ATTESTATION_VERSION_CHANNEL,
  payload: AttestationVersionDecision,
  result: Schema.Literals(["approved", "revoked", "cancelled"]),
  handler: Effect.fn("desktop.ipc.attestation.decide")(function* (request, event) {
    yield* trustedCaller(event);
    const verifier = yield* DesktopAttestation.DesktopAttestation;
    return yield* verifier.decideVersion(request);
  }),
});

export const configureAttestationAuthentication = DesktopIpc.makeIpcMethod({
  channel: Channels.CONFIGURE_ATTESTATION_AUTHENTICATION_CHANNEL,
  payload: Schema.Void,
  result: Schema.Boolean,
  handler: Effect.fn("desktop.ipc.attestation.configureAuthentication")(function* (_, event) {
    yield* trustedCaller(event);
    const verifier = yield* DesktopAttestation.DesktopAttestation;
    return yield* verifier.configureAuthentication;
  }),
});
