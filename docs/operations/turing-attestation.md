# Turing confidential-VM fork

This fork adds a device-side attestation gate to the T3 client. A small status
indicator sits above the composer. Required checks run before dispatch. When
they do not pass, the user can explicitly allow unverified sending for that
conversation until the app closes. A different origin or conversation asks
again. The details show the actual proof state and let the user require
verification again. Cancellation sends nothing. Attachment metadata and bytes
use the same conversation permission. Stop and tool approvals remain available.

The gate uses the same owned hardware-verification core and pinned Tinfoil SDK
as KiapChat. Cryptographic checks run in the installed verifier on the user's
device. The client reads its result through native IPC, not from the VM's UI or
a server-supplied ready flag. For a remote T3 environment, the native client also
checks that its HTTPS public key matches the VM's verified key commitment.
Chromium also verifies the actual TLS transport certificate before allowing a
remote connection. Approved server-key pins remain enforced even when fresh
attestation is unavailable. New hosts retain ordinary certificate validation;
connecting to them does not make them attested. Preview browser sessions are
separate and retain normal website access.

## Trust and scope

The verified checks are VM hardware/firmware, a connection-key commitment and
the exact approved Tinfoil release. The mutable VM software and administrator
remain trusted. A compromised guest and physical side-channel attacks are outside
this deployment's current trust model. Separate proof of exclusive key custody,
measured application code and actual request routing is not implemented. Other
model providers do not become confidential. Disk encryption and storage-key release
have their own deployment acceptance; the status does not attest them.

Details separate the agent environment from the selected inference endpoint and
name their configured origins. A local device is not presented as the VM used for
its inference proxy. Individual checks show green passes, yellow checking or
trusted assumptions, and red failures. Trusted assumptions are not failed checks
or verified guarantees. Chat permission follows the required hardware, connection
and selected-inference policy. Direct ChatGPT and Claude connections explicitly
report that TEE attestation is not offered; an unknown provider is not configured.

A client without a trusted verifier reports that verification is unavailable.
It requires explicit conversation consent rather than trusting a server assertion.
The mobile adapter verifies evidence inside the signed app; see
[mobile setup](mobile-attestation.md). Native acceptance remains platform-specific.

## Server and adapter boundaries

The T3 backend matches upstream stable `v0.1.6`. Attestation requires a separate
host proof agent, not changes to T3's messaging, provider or authentication APIs.
The unrelated new-thread retry workaround is not part of the current backend.

The shared client gate consumes normalized checks. Vendor-specific quote and
release verification stay in adapters. Current adapters cover AMD SEV-SNP and
Tinfoil; other TEE formats still require a verifier and approved policy. A remote
claim that a service uses a TEE is not evidence.

Inference results are scoped to provider instances with client-owned
`inference:<instanceId>` checks. A Tinfoil result does not verify ChatGPT or
Claude. Protected device policy can list `inferenceProviderIds` for aliases of
the same configured attested endpoint. `tlsSpkiSha256` preserves the independently
approved connection key when the proof service is unavailable. These settings
contain public trust data, never API keys or pairing credentials.

Keep service recipes under `integrations/confidential-vm` separate from changes
to upstream T3 code. Check the fork diff against each new stable upstream tag;
keep compatibility fixes independent so they can be removed when upstream fixes
them. Native clients must retain their controlled signing/update channel.

## Codex updates from T3

Use an official OpenAI standalone Codex installation owned by the T3 server user
to enable the normal provider **Update now** action. A custom launcher is treated
as externally managed. This deployment accepts official stable Codex release
packages and trusts OpenAI's release pipeline; T3 Attested and the owned verifier
continue to use controlled source builds.

Keep the standalone runtime home separate from each existing account/provider
home. The installer uses the runtime home as `CODEX_HOME`; T3's **CODEX_HOME path**
continues to point at the existing profile. Preserve that profile, its credentials
and inference URL. Point **Binary path** at the genuine standalone Codex entrypoint.
Set these non-secret variables in the T3 server's startup environment. Upstream
v0.1.6 does not forward provider-instance environment overrides to maintenance
commands, so setting them only in the provider editor is insufficient:

- Set `CODEX_INSTALL_DIR` to the standalone installation's visible `bin` directory.
- Set `CODEX_NON_INTERACTIVE=1` so installation does not prompt to launch Codex or
  remove another installation.
- Prepend that directory to the existing `PATH`. Retain the existing tools and,
  on hardened Linux hosts, the already approved system `bwrap` path.

Retain catalogue generation when retiring a launcher that refreshes Tinfoil model
metadata. Run the existing catalogue script through a user-owned scheduled job;
it fetches model metadata, not conversation data. A local job should stop making
requests when its T3 server is not running. On Linux use an existing user service
manager and keep `NoNewPrivileges=true`; check that the timer starts after reboot.
Do not disable the T3 service's privilege restrictions to install an updater.

Then use **Settings → Providers**, select the environment and provider, open its
update indicator and choose **Update now**. Check the resulting version, model
inventory and a harmless sandbox command before accepting the change. Keep the
previous executable path and release for rollback. Updating Codex does not approve
a new Tinfoil enclave release or change the client attestation policy.

## Set up a device

1. Build T3 using the repository's normal build instructions.
2. Initialize `integrations/confidential-vm/vendor/tinfoil-js` with
   `git submodule update --init --recursive`.
3. In that SDK checkout run `npm ci` and
   `npm run build -w @tinfoilsh/verifier`. Its source revision is pinned.
4. Copy `integrations/confidential-vm/config.example.json` to a machine-local,
   ignored file. Fill in your VM, owner identity and reviewed executable paths
   and hashes. Never put an API key or login token in this file.
5. Run `python3 integrations/confidential-vm/render.py --config CONFIG --output RUNTIME`.
   Choose a fresh runtime directory outside Git. Review the rendered recipes
   before installing them. They preserve the existing gateway, sandbox, browser
   and local-proxy integration code without embedding personal infrastructure.
6. Install the public-evidence service on the VM and the local verifier service
   on the device. The VM keeps the inference API key. The device needs only
   public evidence and its existing authenticated Tailscale connection.
7. Install the rendered `attestation-client.json` at
   `$T3CODE_HOME/attestation-client.json`, owned by the current user, mode `0600`.
   Its allowed environment origins bind verification to the selected connection.
8. Review an inference release with `node release-decision.mjs review` in the
   rendered attestation directory. Approve only the explicitly chosen tag and
   deployment digest. No owner approval or credential is included in the fork.

Use the normal T3 provider setup to retain ChatGPT/Claude accounts. The local
Tinfoil provider points at the local guard's `/v1` URL. Existing VM-hosted T3 may
keep its provider configuration: the fork's trusted desktop client gates new
conversation data before sending it to that environment.

The public evidence endpoint requires the Tailscale owner identity and returns
raw proof data, not a trusted verified flag. The laptop verifier checks signatures,
fresh nonces, the firmware/TCB policy, the approved inference release and HTTPS
key commitment. A new request waits for current proof. Unknown releases and
failed evidence never become verified through an override. A client override
does not alter server access rules, certificate pins, tool approvals or the
inference gateway's own release policy.

## Review build changes

In an installed T3 Attested client, open the verification indicator and select
**Review versions**. VM boot firmware and inference releases have separate
reviews. **View changes**, **View source** and **Proof details** show the available
signed metadata and source links. An absent exact source mapping is stated
explicitly. A publisher signature does not establish that a change is safe.

**Approve exact build** requires device authentication and fresh matching
evidence. It saves only that fingerprint on this device. It does not install
firmware, approve future builds or change another device's approvals.
**Revoke approval** removes trust in that exact build and invalidates current
verification. Closing a pending review cancels approval.

macOS uses device-owner authentication, Windows uses Windows Hello, and mobile
uses the system biometric or device-credential prompt. Linux uses Polkit; the
**Set up system authentication** action installs the bundled `auth_self` rule
after a one-time administrator prompt. Missing system authentication fails
closed. A browser-only client cannot approve builds. T3's agent server does not
receive an approval endpoint or authority to change device trust.

## Test and recovery

Run `python3 integrations/confidential-vm/test.py` after building the pinned SDK.
`T3_TINFOIL_SDK_SOURCE` may select an existing clean checkout at the same pinned
revision. The test renderer uses synthetic endpoints and no credentials.

Client tests cover checking/failure/pass/expiry, environment substitution,
monotonic expiry, send checks and attachment refusal. Desktop tests cover the
owner-device verifier boundary and connection-key mismatch. The browser suite
tests the visible status and retry controls. Live hardware and a real model
reply must be checked separately on each accepted installation.

This is source storage, not a VM image or customer-data backup. Secrets, chats,
session databases, runtime logs, pairing codes and machine-local trust decisions
are excluded. Rebuild prerequisites and source pins remain explicit. Full
reproducible-build, measured-workload and customer-production acceptance are
separate gates.

Retain the previous public provider configuration before changing a live route.
On an intentional rollback, stop only the dedicated local services while idle,
restore that exact configuration and restart the previous client. Preserve chat
and account homes. Never reset Tailscale or remove unrelated VM services.
Before any VM restart, verify working out-of-band recovery access. Source
recovery never authorizes another VM restart or a key export automatically.

## Licenses

The fork retains the upstream MIT license. The pinned Tinfoil SDK is Apache-2.0;
its license and dependency notices remain in the submodule. The optional Codex
instruction template retains its Apache-2.0 source license under
`integrations/confidential-vm/LICENSES`. No vendor executable is committed.

## Validation limits

The long guest-timeline auto-follow browser check can fail with a bootstrap
convergence error also reproduced on unchanged upstream code. It remains enabled.
Passing client checks does not replace live hardware verification on each device.
Automatic upstream desktop updates are disabled by default in this fork so an
unmodified upstream client cannot silently replace the gate.

## Desktop installation

Use the normal desktop artifact builder and install the complete packaged app. A development Electron runtime is not an installed app: macOS can start it without the source entry argument when opening a notification or URL, displaying Electron's default page. The fork uses its own desktop bundle identifier and product name.

The packaged bootstrap reads an optional `t3-attested-launch.json` from the app resources, containing only an absolute `home` path and numeric `port`. Installation can retain an existing T3 home this way. Without this file it uses `~/.t3-attested` and port3773. Explicit environment values still take precedence. No API keys belong in this file. Upstream auto-updates and telemetry stay disabled.
