import type { DesktopIpcInvokeEvent } from "../ipc/DesktopIpc.ts";

export function isApprovalSender(
  event: DesktopIpcInvokeEvent | undefined,
  main: { readonly contentsId: number; readonly frameId: number },
  applicationUrl: string,
): boolean {
  const frame = event?.senderFrame;
  if (
    !frame ||
    frame.parent !== null ||
    event?.sender.id !== main.contentsId ||
    frame.frameTreeNodeId !== main.frameId
  )
    return false;
  try {
    const actual = new URL(frame.url);
    const expected = new URL(applicationUrl);
    return (
      actual.protocol === expected.protocol &&
      actual.host === expected.host &&
      actual.pathname === expected.pathname &&
      !actual.username &&
      !actual.password
    );
  } catch {
    return false;
  }
}
