interface ProofResponse {
  readonly status: number;
  readonly body?: { cancel(): Promise<unknown> } | null;
}
/** @public This declaration types the shared JS entry also copied into the standalone verifier. */
export function createProofCollector(
  wait?: (milliseconds: number) => Promise<void>,
): <T extends ProofResponse>(request: () => Promise<T>) => Promise<T>;
