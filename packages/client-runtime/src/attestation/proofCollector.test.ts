import { expect, it } from "vite-plus/test";
import { createProofCollector } from "./proofCollector.mjs";

it("serializes hardware checks through the collector cooldown", async () => {
  let release!: () => void;
  let entered!: () => void;
  const cooling = new Promise<void>((resolve) => {
    entered = resolve;
  });
  let requests = 0;
  const collect = createProofCollector(
    () =>
      new Promise<void>((resolve) => {
        release = resolve;
        entered();
      }),
  );
  const request = async () => {
    requests++;
    return { status: 200 };
  };
  await collect(request);
  const next = collect(request);
  expect(requests).toBe(1);
  await cooling;
  release();
  await expect(next).resolves.toEqual({ status: 200 });
  expect(requests).toBe(2);
});

it("retries one busy hardware request after the minimum collector interval", async () => {
  const waits: number[] = [];
  let requests = 0;
  const collect = createProofCollector(async (milliseconds) => {
    waits.push(milliseconds);
  });
  const result = await collect(async () => ({ status: ++requests === 1 ? 429 : 200 }));
  expect(result.status).toBe(200);
  expect(requests).toBe(2);
  expect(waits[0]).toBe(2100);
});

it("does not retry other errors or create an unbounded busy loop", async () => {
  for (const status of [400, 403, 429, 503]) {
    let requests = 0;
    const collect = createProofCollector(async () => {});
    const result = await collect(async () => {
      requests++;
      return { status };
    });
    expect(result.status).toBe(status);
    expect(requests).toBe(status === 429 ? 2 : 1);
  }
});

it("bounds pending checks and lets the queue recover after a request fails", async () => {
  let fail!: (reason: Error) => void;
  const collect = createProofCollector(async () => {});
  const first = collect(
    () =>
      new Promise<{ status: number }>((_, reject) => {
        fail = reject;
      }),
  );
  const queued = [
    collect(async () => ({ status: 200 })),
    collect(async () => ({ status: 200 })),
    collect(async () => ({ status: 200 })),
  ];
  await expect(collect(async () => ({ status: 200 }))).rejects.toThrow("pending hardware checks");
  fail(new Error("quote unavailable"));
  await expect(first).rejects.toThrow("quote unavailable");
  await expect(Promise.all(queued)).resolves.toHaveLength(3);
});
