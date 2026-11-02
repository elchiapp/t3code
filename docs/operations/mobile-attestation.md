# Mobile attestation fork

The mobile client connects directly to the existing confidential-VM T3 server
through Tailscale. Codex, tools and conversation state stay on the VM. The phone
verifies public evidence itself. No laptop verifier or proxy is used at runtime.

The owned browser verifier runs in an isolated, nonpersistent WebView inside the
signed app. Its resource hash is pinned in native app configuration. It uses the
same owned SNP evaluator, certificate/firmware bindings and pinned official
Tinfoil SDK as the desktop guard. The VM supplies public proof data, never
executable verification code or a trusted ready boolean.

Native transport protection applies to the actual connection. On iOS, ATS leaf
SPKI pinning protects HTTP requests and a SocketRocket security policy checks
WebSocket certificate trust and the same SPKI. On Android, the app network
security configuration and React Native HTTP/WebSocket client builders enforce
the pin. Ordinary certificate validation stays enabled. A separate successful
TLS probe is not used as permission to send over another connection.

For the current HTTP public-proof service, iOS uses the VM's Tailscale DNS name
with a scoped ATS exception. The native request interceptor permits only the
exact public-proof POST on HTTP and removes authentication and cookie headers.
Other HTTP requests to that hostname are upgraded to HTTPS. HTTPS certificate
validation and key pins remain required. Android permits public-proof HTTP only
to its separately configured Tailscale IP.

The shared command and attachment gates require fresh proof. Missing native
protection, unknown inference releases, bad signatures, wrong key commitments,
expiry or an unavailable verifier require explicit user confirmation before new
sends. Consent stays with that origin and conversation for the current app
session; the details can revoke it. A new conversation asks again. Changing the verifier drops
cached permission and refuses results still pending from the previous verifier.
The details remain honest about unmeasured VM software, exclusive key custody
and actual VM inference routing. Those protections are not supplied by this fork.

## Build inputs

Use a reviewed machine-local JSON configuration with these fields:

- `modelOrigin`: the exact HTTPS origin of the VM inference proxy.
- `environmentOrigins`: approved HTTPS T3 origins on that same VM hostname.
- `proofOrigin`: public-evidence endpoint, HTTPS or an explicit Tailscale IPv4
  HTTP endpoint. Only public nonces and hardware proof use that HTTP endpoint.
- `tlsSpkiSha256`: independently approved VM connection-key fingerprint.
- `proofPolicy`: the reviewed hardware/firmware and inference verification policy.
- `ownerApprovals`: previously approved exact Tinfoil endpoint/tag/digest records.
  This is not approval for future releases.

Do not include API keys, pairing tokens or session databases. Start from the
existing owner-approved public policy or review a new baseline out of band;
do not trust a policy or fingerprint merely because the VM returns it.

Initialize the pinned verifier SDK submodule and build `@tinfoilsh/verifier` with
its locked dependencies. Then run from the repository root:

```sh
node integrations/confidential-vm/mobile/build-verifier.mjs CONFIG_JSON PINNED_SDK_SOURCE
T3_NATIVE_CLIENT_CACHE=off APP_VARIANT=development vp run mobile:install ios --prepare
```

The builder checks the SDK revision, clean source and owned verifier source
hashes. Machine-local policy and generated assets live under
`apps/mobile/.attestation-build`, which is ignored by Git. The verifier's Apache
and MIT dependency notices are included in the mobile third-party notice list.
Keep private build artifacts out of the upstream shared cache.

The fork has independent app identifiers and URL schemes. It does not use the
upstream Expo update channel, upstream cloud identity or upstream observability
configuration. Configure the owner's signing/team and distribution records
before producing device builds or submitting to TestFlight/Play. No upstream
App Store application ID is used.
Set `T3CODE_IOS_TEAM_ID` to the selected owner's Apple Developer team before
generating a signed iOS project. No upstream team is selected by default.

## Acceptance and delivery

Tests using injected proof operations are unit evidence. Running the actual
bundled verifier on fresh public evidence tests the cryptographic bundle, but
neither substitutes for native simulator/device acceptance.

Verify pairing to the VM, actual required-proof success, wrong-certificate and
wrong-proof refusal, expired-proof refusal, attachment gating, background/resume
and reconnection. Retain the incomplete label and all unverified protections.
A standalone Release/preview build must run with the laptop and Metro server
unavailable. A simulator `.app` cannot be installed on a physical iPhone.

TestFlight lets the owner install remotely without a cable. Each beta build
expires after 90 days. Use replacement uploads or production App Store
review/distribution for longer-lived delivery. An ad hoc device build requires
that iPhone's UDID in its provisioning profile. A Metro-dependent development
client does not satisfy the independent-phone acceptance requirement.

Current owner-approved release policy is baked into the first build. An unknown
future Tinfoil release is never marked verified without a reviewed policy update;
refresh or a conversation override never approves a release. The inference
service can still refuse requests under its own release policy. App signing and distribution,
physical iPhone testing, Android native acceptance and independent production
security review are separate release gates.
