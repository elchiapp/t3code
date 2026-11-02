const { withInfoPlist, withAndroidManifest, withDangerousMod } = require("expo/config-plugins");
const fs = require("node:fs");
const path = require("node:path");

module.exports = function withDeviceAttestation(config) {
  const directory = path.join(__dirname, "../.attestation-build");
  const policy = JSON.parse(fs.readFileSync(path.join(directory, "policy.json"), "utf8"));
  const nativePolicy = Object.fromEntries(
    [
      "modelOrigin",
      "inferenceOrigin",
      "proofOrigin",
      "environmentOrigins",
      "tlsSpkiSha256",
      "tlsSpkiBase64",
      "hostname",
      "verifierSha256",
    ].map((key) => [key, policy[key]]),
  );
  const iosPolicy = { ...nativePolicy };
  if (Array.isArray(policy.inferenceProviderIds)) {
    nativePolicy.inferenceProviderIds = policy.inferenceProviderIds;
    iosPolicy.inferenceProviderIds = policy.inferenceProviderIds;
  }
  const publicProof = new URL(policy.proofOrigin);
  if (publicProof.protocol === "http:") {
    publicProof.hostname = policy.hostname;
    iosPolicy.proofOrigin = publicProof.origin;
  }
  config = withInfoPlist(config, (next) => {
    next.modResults.T3AttestationPolicy = iosPolicy;
    const ats = next.modResults.NSAppTransportSecurity ?? {};
    ats.NSAllowsArbitraryLoads = false;
    ats.NSAllowsArbitraryLoadsInWebContent = false;
    ats.NSAllowsLocalNetworking = true;
    // iOS 17+ requires an explicit IP-range exception for Tailnet HTTP servers.
    ats.NSExceptionDomains = {
      ...ats.NSExceptionDomains,
      "100.64.0.0/10": { NSExceptionAllowsInsecureHTTPLoads: true },
    };
    if (publicProof.protocol === "http:") {
      ats.NSExceptionDomains = {
        ...ats.NSExceptionDomains,
        [policy.hostname]: {
          NSIncludesSubdomains: false,
          NSExceptionAllowsInsecureHTTPLoads: true,
        },
      };
    }
    ats.NSPinnedDomains = {
      ...ats.NSPinnedDomains,
      [policy.hostname]: {
        NSIncludesSubdomains: false,
        NSPinnedLeafIdentities: [{ "SPKI-SHA256-BASE64": policy.tlsSpkiBase64 }],
      },
    };
    next.modResults.NSAppTransportSecurity = ats;
    return next;
  });
  config = withAndroidManifest(config, (next) => {
    const application = next.modResults.manifest.application[0];
    application.$["android:networkSecurityConfig"] = "@xml/t3_attestation_network_security";
    application.$["android:usesCleartextTraffic"] = "false";
    return next;
  });
  return withDangerousMod(config, [
    "android",
    (next) => {
      const resources = path.join(next.modRequest.platformProjectRoot, "app/src/main/res");
      fs.mkdirSync(path.join(resources, "raw"), { recursive: true });
      fs.mkdirSync(path.join(resources, "xml"), { recursive: true });
      fs.writeFileSync(
        path.join(resources, "raw/t3_attestation_policy.json"),
        JSON.stringify(nativePolicy),
      );
      const proof = new URL(policy.proofOrigin);
      const cleartext =
        proof.protocol === "http:"
          ? `<domain-config cleartextTrafficPermitted="true"><domain includeSubdomains="false">${proof.hostname}</domain></domain-config>`
          : "";
      fs.writeFileSync(
        path.join(resources, "xml/t3_attestation_network_security.xml"),
        `<?xml version="1.0" encoding="utf-8"?><network-security-config><base-config cleartextTrafficPermitted="false"/><domain-config cleartextTrafficPermitted="false"><domain includeSubdomains="false">${policy.hostname}</domain><pin-set><pin digest="SHA-256">${policy.tlsSpkiBase64}</pin></pin-set></domain-config>${cleartext}</network-security-config>`,
      );
      return next;
    },
  ]);
};
