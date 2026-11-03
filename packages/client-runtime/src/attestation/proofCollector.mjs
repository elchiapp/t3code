export function createProofCollector(
  wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
) {
  let tail = Promise.resolve();
  let pending = 0;
  return (request) => {
    if (pending >= 4)
      return Promise.reject(Error("Too many pending hardware checks. Check again."));
    pending++;
    const run = tail.then(async () => {
      let response = await request();
      if (response.status === 429) {
        await response.body?.cancel().catch(() => {});
        await wait(2100);
        response = await request();
      }
      return response;
    });
    // The quote service has a global cooldown; review and admission must share this device queue.
    tail = run
      .then(
        () => wait(2100),
        () => wait(2100),
      )
      .then(
        () => {
          pending--;
        },
        () => {
          pending--;
        },
      );
    return run;
  };
}
