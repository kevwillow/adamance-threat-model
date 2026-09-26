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

⚠️ **Corrected 2026-09-05. This read "This means the public copy on adamance.dev overstates it
today", and it had already stopped being true when it was published.** TMI-02 below records the copy
being corrected on 2026-09-04: the front page now reads "every artifact it fetches is
signature-checked". The two sentences sat in one file at one commit saying opposite things about the
same web page, which is the failure this document's own rule exists to prevent — a correction was
filed in the register and never propagated to the prose that stated the fault. What the paragraph
above still establishes is unchanged and is the reason the wording mattered: the script is one of the
things fetched and it is the one thing not checked. That gap is real, it is unfixable by a signature,
and TMI-07 carries what would actually close it.

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

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMIV-01 | Someone serves a different agent binary | The gateway verifies every artifact with `bundleverify.Verify` before a byte leaves it, and answers 503 rather than serving something that fails (`src/api-gateway/internal/handlers/installers/agent_install.go:254`). The error string distinguishes "nobody signed it" from "somebody changed it", so you can tell a mistake from an attack. | **BUILT** |
| TMIV-02 | The gateway is the one lying | This is the honest limit of the header path. `verify_download` accepts either an `EXPECTED_SHA256` you paste from the console or the gateway's own `X-Content-SHA256` header (`src/api-gateway/internal/handlers/installers/agent_install.sh:125`). A hash from the same server as the bytes proves transport, not provenance. The script says so out loud and warns when it takes that path rather than passing quietly. | **BUILT, and bounded** |
| TMIV-03 | Nobody pins anything | The script refuses to install with no digest at all, from either source. There is no "carry on anyway" branch. | **BUILT** |
| TMIV-04 | The verifying key is one an attacker already has | `bundleverify.Verify` falls back to the in-repo dev public key when no key file is configured (`src/common/bundleverify/verify.go:81-83`). ⚠️ The agent-binary handler forbids that state before it can be reached: it 503s when either `serve_dir` or `pubkey_file` is unset, so the fallback is unreachable on that path. Boot also refuses to start in prod posture with the policy-bundle key unpinned (`src/api-gateway/internal/config/config.go:859`). | **BUILT** |

### The release behind the bytes

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMIV-05 | Release signed with a key anyone can clone | ⚠️ **Not held.** Every release built so far used the committed dev key. Two open gaps carry this, and one of them is the single gate to a shippable release. Until a production key exists, the entire Ed25519 chain above roots in a key that ships in the repository. | **OPEN** |
| TMIV-06 | CI account or workflow compromise | Nothing. No provenance attestation, no two-party release, no reproducible build. `scripts/sign-agent-binaries.sh` signs whatever is staged in `dist/`. | **DESIGNED at best** |
| TMIV-07 | Downgrade to an older release that was signed and is now known bad | Nothing. A signature says we made it, never that it is still the one you should run. No version floor, no revocation of a published artifact. | **NOT MODELLED** |
| TMIV-08 | Upstream image or dependency compromise | Images pinned by `@sha256`, weekly Trivy scan with a blocking threshold, cosign-verified digests at setup. That bounds substitution. It does nothing about a malicious change upstream that gets a legitimate digest. | **PARTIAL** |

### After it runs

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMIV-09 | Install fails halfway and leaves the box permissive | Not modelled. Nothing describes the state of a host after a partial agent install, or what a half-configured PAM and sshd allow. | **NOT MODELLED** |
| TMIV-10 | Upgrade or rollback swaps in an unverified binary | The upgrade path verifies the same way the install does. Rollback to a previously verified artifact is fine by signature and is exactly the downgrade case above. | **PARTIAL** |
| TMIV-11 | Proxy environment variables redirect the fetch | Not modelled. `http_proxy` and friends are read by curl and nothing pins the peer beyond TLS. | **NOT MODELLED** |

## What we do not defend against

- An attacker who holds the release signing key. Everything here trusts that key by construction, so
  there is no control below it. Custody is the control, and it is a human procedure.
- A malicious change in an upstream project that ships with a legitimate signature and digest. We pin
  what we are given. We do not audit FreeIPA.
- The first fetch of the install script. See the top of this document.

## Still open

| ID | Item | Why it is still open | Status |
| --- | --- | --- | --- |
| TMI-01 | No production signing key has ever been used | Every artifact so far is signed with the key in the repo, so the chain is presentational until custody exists. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The refusal MECHANISM is built and wired: scripts/sign-agent-binaries.sh:80 dies when REQUIRE_PROD_KEY=true and BUNDLE_SIGNING_KEY is unset, so a real release cannot be signed with the committed dev key. The KEY itself still does not exist — the key gap was re-measured 2026-09-15 at b888b4fd on four independent legs, each with its own positive control (tracked files, Actions secrets total_count=0 against workflows=12, both env vars unset against a SENTINEL control, the maintainer's local key directory empty), and REPRODUCES. So every artifact the pipeline can produce is still rooted in the repo's dev key. MISSING: the one human act — `make signing-ceremony` and a passphrase. NOT CHECKED: those four legs were not re-run; this verdict rests on a six-day-old re-measurement. Evidence: `scripts/sign-agent-binaries.sh:80` | **NOT_BUILT** |
| TMI-02 | The public claim was wider than the control | ✅ Copy corrected 2026-09-04. `index.html` said the installer "checks the signature on everything it fetches", which cannot be true of the script arriving in the same pipe, and `threat-model.html` said the honest version on the same site. The front page now reads "every artifact it fetches is signature-checked", so the two pages agree. What is still owed is the control that would let somebody not take the script on trust at all: a published release commit SHA and tarball SHA-256 on the main site, and a verify-then-run path. See TMI-07. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** HOLDS — the copy clause the row was corrected for: index.html:603 now reads "every artifact it fetches is signature-checked before it unpacks or runs any of it" and names the limit out loud ("The one thing that cannot check itself is the script you just piped into a shell"), so the front page and threat-model.html agree. The corrected text is not disputed. MISSING — the clause the row itself says is still owed, "a published release commit SHA and tarball SHA-256 on the main site": no commit SHA is published anywhere on the site. A `\b[0-9a-f]{40}\b/\b[0-9a-f]{12}\b` sweep over every .html on the site returns zero hits; the control on the same walk, `grep -c 'adamance' index.html` -> 26, proves the files are being read, so that zero is a real absence and not a broken search. No tarball SHA-256 exists either. The residual is delegated to TMI-07 by the row's own last sentence. Evidence: `index.html:603` · `index.html:584` | **PARTIAL** |
| TMI-03 | `agent_binary` is missing from the shipped prod config | `configs/api-gateway/api-gateway.dev.yml:230` sets `serve_dir` and `pubkey_file`. The prod config has no `agent_binary` block and `deploy/setup/install.sh` never writes one, so a stock production gateway 503s the one-line agent install. Fails closed, which is right, but the second of the two advertised steps does not work. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Confirmed unchanged, and the row's own citation has drifted. `agent_binary` exists in exactly one config file in the tree: configs/api-gateway/api-gateway.dev.yml:279-281 (serve_dir :280, pubkey_file :281). A grep for agent_binary/agent-binaries/AgentBinary across configs/api-gateway/api-gateway.prod.yml, deploy/setup/ and deploy/ha/ returns NOTHING; the control is that the same walk finds the bundle server's serve_dir/pubkey_file at api-gateway.prod.yml:215-216, so the walk reaches prod.yml and the absence is real. The handler's fail-closed branch is byte-identical to the citation on record: src/api-gateway/internal/handlers/installers/agent_install.go:246-250 answers 503 when ServeDir or PubKeyFile is empty. STALE ADDRESS: the row cites api-gateway.dev.yml:230; the block is at 279 today (recorded at 260, corrected to 262 on 2026-09-15 — it has moved again). The claim is right, the line number is not. Evidence: `configs/api-gateway/api-gateway.dev.yml:279` · `configs/api-gateway/api-gateway.dev.yml:280` · `configs/api-gateway/api-gateway.prod.yml:215` · `src/api-gateway/internal/handlers/installers/agent_install.go:246` | **NOT_BUILT** |
| TMI-04 | No release provenance | Nothing attests which commit, which runner, or which inputs produced an artifact. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The row's absolute — "Nothing attests which commit, which runner, or which inputs produced an artifact" — is overstated on two of its three halves, and the mechanism that falsifies it has never once run. WRITTEN: `.github/workflows/release.yml:329-332` signs every release artifact with keyless Sigstore (`cosign sign-blob --bundle`) and then verifies it against a Fulcio identity pinned to the repository, the workflow file and the ref (`--certificate-identity-regexp`, `--certificate-oidc-issuer https://token.actions.githubusercontent.com`). That binds runner and commit. NOT written: any SLSA or in-toto BUILD-PROVENANCE predicate — a grep for `attest-build-provenance/slsa-github-generator/in-toto/--type slsaprovenance` across `.github/workflows/` returns nothing — and docker/build-push-action's own provenance is explicitly switched off (`provenance: false`, `release.yml:171` and `container-build.yml:79`). 🚨 **Measured 2026-09-21 and missed by both passes that reviewed this row: it has never executed.** GitHub Actions is disabled at the repository level (`gh api …/actions/permissions` → `{"enabled":false}`) and there are **0 published releases**, so no artifact has ever carried one of these signatures. The control is code, not evidence. Evidence: `.github/workflows/release.yml:329` · `.github/workflows/release.yml:331` · `.github/workflows/release.yml:171` · `.github/workflows/container-build.yml:79` · `.github/workflows/release.yml:216` | **PARTIAL** |
| TMI-05 | Downgrade is unbounded | A correctly signed old release installs cleanly forever. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** A downgrade floor DOES exist — and it is the wrong artifact, which is why this row is not PARTIAL. src/api-gateway/internal/bundle/bundle.go:93-97 defines FloorStatePath, a monotonic highest-built_at floor persisted across restart, with a bundle.downgrade_refused audit event and tests at internal/bundle/downgrade_test.go:62 and :120. Every one of those is inside internal/bundle — the POLICY BUNDLE server. The release/agent-binary path has no floor at all: in the shipped installer script, `version` appears only as a post-download sanity check (agent_install.sh:177-179), an install log line (:198-199), and an idempotency no-op when the staged version already matches (:361). Nothing compares an installed or offered version against a minimum, so a correctly-signed old release installs cleanly. MISSING also: revocation of a published artifact — `internal/revocation` and sshca/krl.go:25 are OpenSSH key revocation lists, not artifact revocation; a concept search for revocation list / revoked artifact / anti-rollback across src/, scripts/, policies/ and deploy/ surfaced nothing else. Evidence: `src/api-gateway/internal/bundle/bundle.go:93` · `src/api-gateway/internal/bundle/downgrade_test.go:62` · `src/api-gateway/internal/handlers/installers/agent_install.sh:177` · `src/api-gateway/internal/handlers/installers/agent_install.sh:361` · `src/api-gateway/internal/sshca/krl.go:25` | **NOT_BUILT** |
| TMI-06 | Partial-install state is undescribed | Nobody has written down what a host looks like when the agent install dies halfway. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** HOLDS for the CONTROL PLANE: the installer design does describe partial-failure state — an idempotency check at the start of every step so a run can be resumed after a partial failure (:172-185), a state-tracking section (:187), and an error model whose unrecoverable row reads 'Roll back what is possible, leave system in a documented partial state' (:265). MISSING for the AGENT, which is what TMI-06 actually names: that doc scopes itself to the `adamance-install` binary and explicitly excludes 'Managing hosts after enrollment (use the agent)' (:16-31). A concept search across the docs for half-installed / partially installed / partial agent install returns only THREAT_MODEL_installer.md:99 — the TMIV-09 row asserting the absence — so no doc describes a host after a half-finished agent install, or what a half-configured PAM and sshd allow. Two code mitigations exist but are not the description asked for: join_install.sh.tmpl preflights before anything is written (:79-80) and clears its staging dir on an EXIT trap (:182), and agent_install.sh's update path does backup -> swap -> health-check -> rollback (:343, :403-409). Against that, one of the two host install paths genuinely DOES half-install: the served path warns and SKIPS the unit file on a systemd-less host, leaving a binary nothing supervises. Evidence: `src/api-gateway/internal/handlers/installers/join_install.sh.tmpl:79` · `src/api-gateway/internal/handlers/installers/join_install.sh.tmpl:182` · `src/api-gateway/internal/handlers/installers/agent_install.sh:403` | **PARTIAL** |
| TMI-07 | There is no verify-then-run path | ⭐ 2026-09-04, ⚖️ **raised by the maintainer before any review found it:** offer a path where the user downloads or clones the repository and verifies it against a hash before running anything, instead of trusting the script. The unfixable gap is that a piped script cannot check itself. The fix is not a signature, it is an alternative: publish the release commit SHA and the tarball SHA-256 on the main site, and document clone-verify-run as the recommended path. Git is a Merkle tree, so one commit SHA covers every byte, and no per-file manifest is needed. Two caveats belong in that copy rather than under it: commit SHAs are still SHA-1 with collision detection, so the tarball SHA-256 is the stronger anchor; and `get.adamance.dev` shares a Cloudflare zone with `adamance.dev`, so publishing the hash on `get.` buys nothing — the separation that makes this worth doing is `adamance.dev` against `github.com`. Blocked today because the source repository is not public and no release exists to hash. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** This row has MOVED since it was written, and acquired a new defect in the move. HOLDS — the clause 'document clone-verify-run as the recommended path': index.html:578-590 now presents it under the heading 'The preferred way · check it before you run it', ahead of the curl/sh path, with `git clone` then `git -C adamance rev-parse HEAD` then `deploy/setup/install.sh`. MISSING — the clause 'publish the release commit SHA and the tarball SHA-256 on the main site': index.html:584 instructs the reader to 'Compare that one line against the release commit published on this site', and no commit SHA is published anywhere on the site. A 40-hex and 12-hex sweep over every .html in the site tree returns zero; the control on the same walk (`grep -c 'adamance' index.html` -> 26) proves the files are read, so the zero is a real absence. No tarball SHA-256 exists either. NET EFFECT: the front page's preferred path now tells people to perform a verification they cannot perform. The row's stated blocker also still holds (0 published releases, repo private) — NOT CHECKED: those gh api calls were not re-run, so that leg is 2026-09-10 data. Evidence: `index.html:581` · `index.html:584` · `index.html:587` | **PARTIAL** |
| TMI-08 | arm64 has never been installed | ⭐ 2026-09-04. arm64 packages are built and the site claims every Pi from the 3 onward on a 64-bit image. Every install test hardcodes amd64, so no arm64 install has ever run. The claim is plausible and untested rather than false, and it stays as a requirement on the code. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The row's own characterisation is accurate and I confirm it. This was measured 2026-09-18 at db63ea4d with a full positive control: no file under deploy/packaging/test/ names arm64 or aarch64 (rc=1, while the same walk for amd64/x86_64 returns both drill files); 0 of the 10 install commands tree-wide name an arm64 artefact; neither drill passes --platform, so the `dpkg -i` runs on the builder's architecture; run-systemd-test.sh:22 pins the amd64 deb and :47 rebuilds PKG_ARCHES=amd64. The MECHANISM holds end to end — build-packages.sh:27 defaults PKG_ARCHES to 'amd64 arm64', release.sh:205 and :207 require the arm64 deb and aarch64 rpm by name, and the arch selector was re-read: join_install.sh.tmpl:89-97 maps aarch64/arm64 -> ARCH=arm64 and refuses 32-bit ARM by name with a reason. MISSING: any exercise that installs an arm64 package. So the site's ARM claim is plausible and untested rather than false, and per the standing rule it stays as a requirement on the code. Evidence: `src/api-gateway/internal/handlers/installers/join_install.sh.tmpl:89` · `src/api-gateway/internal/handlers/installers/join_install.sh.tmpl:91` | **NOT_BUILT** |

## Where this came from

The code named in the tables above. Signing: `scripts/sign-agent-binaries.sh`. Verification: `src/common/bundleverify/verify.go`.
