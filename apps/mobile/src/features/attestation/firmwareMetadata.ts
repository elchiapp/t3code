import * as Base64 from "effect/encoding/Base64";

export interface GoogleFirmwareEvidence {
  readonly measurement: string;
  readonly endorsementBase64: string;
  readonly rootBase64: string;
}

async function publicBinary(url: string, limit: number): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(url, {
      redirect: "error",
      credentials: "omit",
      signal: controller.signal,
    });
    if (!response.ok || Number(response.headers.get("content-length")) > limit)
      throw new Error("Google firmware evidence is unavailable or too large.");
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > limit) throw new Error("Google firmware evidence exceeds the size limit.");
    return Base64.encode(bytes);
  } finally {
    clearTimeout(timeout);
  }
}

const cache = new Map<string, Promise<GoogleFirmwareEvidence>>();
let root: Promise<string> | undefined;
export async function googleFirmwareEvidence(measurements: ReadonlyArray<string>) {
  return Promise.all(
    [...new Set(measurements)].map((measurement) => {
      if (!/^[a-f0-9]{96}$/.test(measurement)) throw new Error("Invalid firmware evidence target.");
      const existing = cache.get(measurement);
      if (existing) return existing;
      while (cache.size >= 32) cache.delete(cache.keys().next().value!);
      root ??= publicBinary("https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt", 8192).catch(
        (cause) => {
          root = undefined;
          throw cause;
        },
      );
      const pending = Promise.all([
        publicBinary(
          `https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/sevsnp/${measurement}.binarypb`,
          131072,
        ),
        root,
      ]).then(([endorsementBase64, rootBase64]) => ({
        measurement,
        endorsementBase64,
        rootBase64,
      }));
      cache.set(measurement, pending);
      void pending.catch(() => cache.delete(measurement));
      return pending;
    }),
  );
}
