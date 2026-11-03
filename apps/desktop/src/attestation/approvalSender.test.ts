import { expect, it } from "vite-plus/test";
import { isApprovalSender } from "./approvalSender.ts";

it("limits approval IPC to the committed T3 main frame and rejects preview, child and missing frames", () => {
  const main = { contentsId: 10, frameId: 20 };
  const event = {
    sender: { id: 10 },
    senderFrame: { url: "t3code://app/#/thread", parent: null, frameTreeNodeId: 20 },
  };
  expect(isApprovalSender(event, main, "t3code://app/")).toBe(true);
  for (const value of [
    undefined,
    { ...event, sender: { id: 11 } },
    { ...event, senderFrame: null },
    { ...event, senderFrame: { ...event.senderFrame, parent: {} } },
    { ...event, senderFrame: { ...event.senderFrame, frameTreeNodeId: 21 } },
    { ...event, senderFrame: { ...event.senderFrame, url: "https://preview.example/" } },
    { ...event, senderFrame: { ...event.senderFrame, url: "t3code://other/" } },
    { ...event, senderFrame: { ...event.senderFrame, url: "t3code://app/preview" } },
    { ...event, senderFrame: { ...event.senderFrame, url: "t3code://user:password@app/" } },
  ])
    expect(isApprovalSender(value, main, "t3code://app/")).toBe(false);
});
