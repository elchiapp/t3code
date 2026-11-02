import { expect, it } from "vite-plus/test";
import { applyAttestedLaunchDefaults } from "./launchDefaults";

it("keeps notification and normal launches on the configured data home without overriding an explicit home", () => {
  const defaults = { home: "/owned/t3-home", port: 3773 };
  const environment: Record<string, string | undefined> = {};
  applyAttestedLaunchDefaults(defaults, environment);
  expect(environment.T3CODE_HOME).toBe(defaults.home);
  expect(environment.T3CODE_PORT).toBe("3773");
  expect(environment.T3CODE_DISABLE_AUTO_UPDATE).toBe("true");
  expect(environment.T3CODE_TELEMETRY_ENABLED).toBe("false");
  environment.T3CODE_HOME = "/explicit/home";
  applyAttestedLaunchDefaults(defaults, environment);
  expect(environment.T3CODE_HOME).toBe("/explicit/home");
});

it.each([
  null,
  { home: "relative/home", port: 3773 },
  { home: "/owned/home", port: 0 },
  { home: "/owned/home", port: 65536 },
  { home: "/owned/home", port: 3.5 },
  { home: "/owned/home", port: 3773, apiKey: "must-not-be-packaged" },
])(
  "rejects invalid or secret-bearing launch configuration before changing the environment: %j",
  (configuration) => {
    const environment = {};
    expect(() => applyAttestedLaunchDefaults(configuration, environment)).toThrow();
    expect(environment).toEqual({});
  },
);
