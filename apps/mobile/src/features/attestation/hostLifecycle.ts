let recover: (() => boolean) | undefined;

export function installVerifierRecovery(handler: () => boolean): () => void {
  recover = handler;
  return () => {
    if (recover === handler) recover = undefined;
  };
}

export function retryVerifierHost(): boolean {
  return recover?.() ?? false;
}
