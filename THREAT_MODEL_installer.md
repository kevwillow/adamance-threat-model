# Threat Model: the installer and the supply chain behind it

> Status: **DRAFT, written 2026-09-01** against `b276339c`. Owner: project maintainer.
> Companion to [`THREAT_MODEL.md`](THREAT_MODEL.md). That one has a single row for "MITM of the
> install script", which is nowhere near enough for a thing you pipe into a root shell. This is the
> rest of it.

---

## What this covers

Two installers, and they do not have the same trust model. Saying so up front, because most of the
confusion here comes from treating them as one thing.

**The control plane installer.** `curl -fsSL https://get.adamance.dev | sh`, which lands as
[`deploy/setup/install.sh`](../deploy/setup/install.sh). It stands up the server. It pulls container
images by `@sha256` digest, requires `cosign` on the box, and refuses to continue without the
toolchain it needs.

**The agent installer.** Served by the gateway itself at `/api/v1/machines/adamance-agent.sh`, from
[`src/api-gateway/internal/handlers/installers/agent_install.sh`](../src/api-gateway/internal/handlers/installers/agent_install.sh).
It brings one machine under management. It fetches the agent binary from the gateway you already
decided to trust.

The second one is in a better position than the first, and the reason is worth stating: by the time
it runs, you have a server, and that server can hold a key.

## The problem you cannot engineer your way out of

A script fetched over the network and piped into a shell runs before anything has checked it. It can
verify everything it downloads afterwards. It cannot verify itself. There is no arrangement of
signatures that fixes this, because whatever would check the signature also arrived in the same pipe.

So the honest claim is narrower than "it checks the signature on everything it fetches before it
unpacks or runs any of it". What is true is that the script verifies every artifact it fetches after
it starts. What gets you to the script is TLS, DNS, and your own decision to trust `get.adamance.dev`.
Nothing more.

⚠️ This means the public copy on adamance.dev overstates it today. The word doing the damage is
"everything", because the script is one of the things fetched and it is the one thing not checked.

## Assets

| Rank | Asset | What it costs you |
| --- | --- | --- |
| 1 | The release signing key (K-06 Ed25519) | Sign anything, and every host accepts it as ours |
| 2 | `get.adamance.dev` and its DNS, TLS and CDN | Serve a different script to every new install |
| 3 | The CI account and release workflow | Same reach as the key, one step further back |
| 4 | The artifact store the gateway serves from | Swap the agent binary before it is signed |
| 5 | Container image tags and digests | Substitute a control-plane component at setup time |

## Adversaries

**A1, external and unauthenticated.** Can reach `get.adamance.dev`, can attempt DNS and BGP tricks,
can serve a response if they get in the path. Cannot sign.

**A8, a compromised release path.** Anyone who reaches the CI account, the workflow, or the signing
key. This is the one that matters, because everything downstream is built to trust exactly what they
now control. Not in the main threat model at all today.

**A9, an upstream project or image.** FreeIPA, Keycloak, OPA, step-ca, Wazuh, OpenBao, and everything
they pull. adamance is a thin layer over other people's code and this is where most of the lines are.

## Trust boundaries

| From | To | Authentication | Status |
| --- | --- | --- | --- |
| Operator's shell | `get.adamance.dev` | TLS server certificate, and nothing else | **inherent, see above** |
| Control-plane installer | Container registry | `@sha256` digest pins, cosign on the box | **BUILT** |
| Agent installer | Gateway binary endpoint | Ed25519 over the artifact, verified server side | **BUILT** |
| Gateway | Its own artifact directory | Detached `.sig` per artifact, K-06 key | **BUILT** |
| Release workflow | Signing key | ⚠️ Only the committed dev key has ever been used | **OPEN** |

## Vectors and controls

### Getting the bytes

| Vector | Control | Status |
| --- | --- | --- |
| Someone serves a different agent binary | The gateway verifies every artifact with `bundleverify.Verify` before a byte leaves it, and answers 503 rather than serving something that fails (`src/api-gateway/internal/handlers/installers/agent_install.go:254`). The error string distinguishes "nobody signed it" from "somebody changed it", so you can tell a mistake from an attack. | **BUILT** |
| The gateway is the one lying | This is the honest limit of the header path. `verify_download` accepts either an `EXPECTED_SHA256` you paste from the console or the gateway's own `X-Content-SHA256` header (`src/api-gateway/internal/handlers/installers/agent_install.sh:125`). A hash from the same server as the bytes proves transport, not provenance. The script says so out loud and warns when it takes that path rather than passing quietly. | **BUILT, and bounded** |
| Nobody pins anything | The script refuses to install with no digest at all, from either source. There is no "carry on anyway" branch. | **BUILT** |
| The verifying key is one an attacker already has | `bundleverify.Verify` falls back to the in-repo dev public key when no key file is configured (`src/common/bundleverify/verify.go:81-83`). ⚠️ The agent-binary handler forbids that state before it can be reached: it 503s when either `serve_dir` or `pubkey_file` is unset, so the fallback is unreachable on that path. Boot also refuses to start in prod posture with the policy-bundle key unpinned (`src/api-gateway/internal/config/config.go:859`). | **BUILT** |

### The release behind the bytes

| Vector | Control | Status |
| --- | --- | --- |
| Release signed with a key anyone can clone | ⚠️ **Not held.** Every release built so far used the committed dev key. Two open gaps carry this, and one of them is the single gate to a shippable release. Until a production key exists, the entire Ed25519 chain above roots in a key that ships in the repository. | **OPEN** |
| CI account or workflow compromise | Nothing. No provenance attestation, no two-party release, no reproducible build. `scripts/sign-agent-binaries.sh` signs whatever is staged in `dist/`. | **DESIGNED at best** |
| Downgrade to an older release that was signed and is now known bad | Nothing. A signature says we made it, never that it is still the one you should run. No version floor, no revocation of a published artifact. | **NOT MODELLED** |
| Upstream image or dependency compromise | Images pinned by `@sha256`, weekly Trivy scan with a blocking threshold, cosign-verified digests at setup. That bounds substitution. It does nothing about a malicious change upstream that gets a legitimate digest. | **PARTIAL** |

### After it runs

| Vector | Control | Status |
| --- | --- | --- |
| Install fails halfway and leaves the box permissive | Not modelled. Nothing describes the state of a host after a partial agent install, or what a half-configured PAM and sshd allow. | **NOT MODELLED** |
| Upgrade or rollback swaps in an unverified binary | The upgrade path verifies the same way the install does. Rollback to a previously verified artifact is fine by signature and is exactly the downgrade case above. | **PARTIAL** |
| Proxy environment variables redirect the fetch | Not modelled. `http_proxy` and friends are read by curl and nothing pins the peer beyond TLS. | **NOT MODELLED** |

## What we do not defend against

- An attacker who holds the release signing key. Everything here trusts that key by construction, so
  there is no control below it. Custody is the control, and it is a human procedure.
- A malicious change in an upstream project that ships with a legitimate signature and digest. We pin
  what we are given. We do not audit FreeIPA.
- The first fetch of the install script. See the top of this document.

## Still open

| ID | Item | Why it is still open |
| --- | --- | --- |
| TMI-01 | No production signing key has ever been used | Every artifact so far is signed with the key in the repo, so the chain is presentational until custody exists. |
| TMI-02 | The public claim was wider than the control | ✅ Copy corrected 2026-09-04. `index.html` said the installer "checks the signature on everything it fetches", which cannot be true of the script arriving in the same pipe, and `threat-model.html` said the honest version on the same site. The front page now reads "every artifact it fetches is signature-checked", so the two pages agree. What is still owed is the control that would let somebody not take the script on trust at all: a published release commit SHA and tarball SHA-256 on the main site, and a verify-then-run path. See TMI-07. |
| TMI-03 | `agent_binary` is missing from the shipped prod config | `configs/api-gateway/api-gateway.dev.yml:230` sets `serve_dir` and `pubkey_file`. The prod config has no `agent_binary` block and `deploy/setup/install.sh` never writes one, so a stock production gateway 503s the one-line agent install. Fails closed, which is right, but the second of the two advertised steps does not work. |
| TMI-04 | No release provenance | Nothing attests which commit, which runner, or which inputs produced an artifact. |
| TMI-05 | Downgrade is unbounded | A correctly signed old release installs cleanly forever. |
| TMI-06 | Partial-install state is undescribed | Nobody has written down what a host looks like when the agent install dies halfway. |
| TMI-07 | There is no verify-then-run path | ⭐ 2026-09-04. The unfixable gap is that a piped script cannot check itself. The fix is not a signature, it is an alternative: publish the release commit SHA and the tarball SHA-256 on the main site, and document clone-verify-run as the recommended path. Git is a Merkle tree, so one commit SHA covers every byte, and no per-file manifest is needed. Two caveats belong in that copy rather than under it: commit SHAs are still SHA-1 with collision detection, so the tarball SHA-256 is the stronger anchor; and `get.adamance.dev` shares a Cloudflare zone with `adamance.dev`, so publishing the hash on `get.` buys nothing — the separation that makes this worth doing is `adamance.dev` against `github.com`. Blocked today because the source repository is not public and no release exists to hash. |
| TMI-08 | arm64 has never been installed | ⭐ 2026-09-04. arm64 packages are built and the site claims every Pi from the 3 onward on a 64-bit image. Every install test hardcodes amd64, so no arm64 install has ever run. The claim is plausible and untested rather than false, and it stays as a requirement on the code. |

## Where this came from

The code named in the tables above. Signing: `scripts/sign-agent-binaries.sh`. Verification: `src/common/bundleverify/verify.go`.
