// @effect-diagnostics nodeBuiltinImport:off - Bootstrap validates the native host's filesystem path before the Effect runtime starts.
import * as NodePath from "node:path";

export function applyAttestedLaunchDefaults(
  input: unknown,
  environment: Record<string, string | undefined>,
): void {
  if (input === null || typeof input !== "object" || Array.isArray(input))
    throw new Error("T3 Attested launch configuration is invalid.");
  const configuration = input as Record<string, unknown>;
  if (
    Object.keys(configuration).some((key) => key !== "home" && key !== "port") ||
    typeof configuration.home !== "string" ||
    !NodePath.isAbsolute(configuration.home) ||
    !Number.isInteger(configuration.port) ||
    Number(configuration.port) < 1 ||
    Number(configuration.port) > 65535
  )
    throw new Error("T3 Attested needs an absolute data home and a valid local port.");
  environment.T3CODE_HOME ??= configuration.home;
  environment.T3CODE_PORT ??= String(configuration.port);
  environment.T3CODE_DISABLE_AUTO_UPDATE = "true";
  environment.T3CODE_TELEMETRY_ENABLED = "false";
  environment.DO_NOT_TRACK = "1";
  environment.T3CODE_ATTESTED_CATALOG = "1";
  environment.T3CODE_DESKTOP_APP_USER_MODEL_ID ??= "io.elchiapp.t3attested.desktop";
}
