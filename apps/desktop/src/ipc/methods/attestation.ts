import { AttestationRequest, AttestationStatus } from "@t3tools/contracts";
import * as Effect from "effect/Effect";
import * as DesktopAttestation from "../../attestation/DesktopAttestation.ts";
import * as DesktopIpc from "../DesktopIpc.ts";
import * as Channels from "../channels.ts";

export const getAttestationStatus = DesktopIpc.makeIpcMethod({
  channel: Channels.GET_ATTESTATION_STATUS_CHANNEL,
  payload: AttestationRequest,
  result: AttestationStatus,
  handler: Effect.fn("desktop.ipc.attestation.get")(function* (request) {
    const verifier = yield* DesktopAttestation.DesktopAttestation;
    return yield* verifier.get(request);
  }),
});
