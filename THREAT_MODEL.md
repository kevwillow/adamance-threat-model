# Threat Model: adamance

> Status: **REVIEWED, and current as of the date below.** Owner: project maintainer.
> Last reviewed: **2026-09-05.** Prior passes: 2026-09-04, 2026-09-02, 2026-09-01, 2026-08-31, 2026-07-11, 2026-05-26, 2026-05-24.
> ⚠️ **Corrected 2026-09-05: this line read "Last reviewed: 2026-09-04" while TM-41 and TM-42, two rows in
> this file, were dated 2026-09-05.** A header that stops a day before the document's own newest row is the
> cheapest possible version of the defect this document keeps finding in itself.
> External review: **2026-09-26.** Read in full by three reviewers; each finding that survived checking is added or corrected in place and dated 2026-09-26, and every corrected sentence quotes what it replaced. Not a whole-document re-measure, so `Last reviewed` is unchanged.
>
> Seven subsystems have their own threat models and are not repeated here:
> [agent accounts](THREAT_MODEL_agent_accounts.md), [the installer](THREAT_MODEL_installer.md),
> [audit anchoring](THREAT_MODEL_audit_anchoring.md), [session recording](THREAT_MODEL_session_recording.md),
> [the Samba AD DC module](THREAT_MODEL_samba_ad_dc.md), [VPN, RADIUS and DNS](THREAT_MODEL_network_modules.md),
> and [Active Directory integration](THREAT_MODEL_ad_integration.md).

---

## How to read this document

**This document is the contract, not a status report.** ⚖️ **OPERATOR RULED, 2026-09-04, after models repeatedly narrowed rows here and on the website to match what was built:** if a threat is technically possible, it stays in the documents, because the documents and this threat model are the contract the code has to meet, not a statement of its current status. A row states a threat and the control the code
has to meet. The status beside it says how far the code has got. A threat is never removed because
nothing implements it yet; it is removed only when it stops being technically possible, which is rare.
A row with no code behind it is a requirement, not a claim, and nobody should cite it as a protection.

Every row carries its own current status and the date it was last checked, and every correction lives
on the row it corrects. That is the whole rule. There is no precedence between sections here and there
should never be one: a security document that tells you which of its own halves to believe has stopped
being a source of truth.

⚠️ **The long second-pass review further down is dated 2026-05-26 and is kept on purpose.** It is a
point-in-time audit, and several items it calls a violation or a hard stop were fixed in the weeks
after. Where that happened, the row says so in place, with the original wording quoted so the
correction cannot be mistaken for the original text. Read a row, not a section.

⚠️ **Corrected 2026-09-04: that promise was not kept in six places, and an outside reader found them
before we did.** Five rows in the 2026-05-26 audit still read as current after a later pass had
overturned them, and one row above the audit named an enforcement mechanism that does not exist in the
tree. All six are corrected in place below and each one quotes what it used to say. The table under the
next heading is a finding aid for those corrections. It is not an instruction about which half of this
document to believe, and it stops being needed once every row it lists carries its own correction.

⭐ **Corrections are the most valuable thing in here.** Where a row once said a control was confirmed
and that turned out to be false, the row says that too, because a gap nobody has looked at is ordinary
and a gap with a tick next to it sends every later reader somewhere else.

### Re-verified against live source on 2026-07-11, and still true

**Contested items that were resolved. Each one now carries its correction in place further down; this
table is the index of them.**

| TM | Contested claim (old narrative) | Live ground truth (2026-07-11) |
|----|----|----|
| TM-10 | "enrollment handler is a stub, never calls FreeIPA" | FALSE; `enrollment/handler.go` calls `HostAdd`/`GetKeytab`/`IssueHostCert` (:514/533/547); join redeem does the same. Fully wired. |
| TM-23 | "❌ VIOLATION: 7 internal clients on TLS 1.2" | api-gateway + wazuh-bridge are TLS 1.3-only (31 `MinVersion: VersionTLS13`, zero `VersionTLS12` in `src/api-gateway`/`src/wazuh-bridge`). **BUT the client-agent join bootstrap still used TLS 1.2 → FIXED this pass (see below).** |
| TM-19 | "second-approver NOT implemented; policies/governance doesn't exist" | Built: `policies/governance/require_approval.rego` + `internal/storage/approval/store.go` + dual-control (opt-in, fail-secure). |
| TM-16 | "bundle.critical never produced; CriticalBundlePath not plumbed" | `scripts/build-policies.sh` has a `critical` target; `bundle.go` fully plumbs `CriticalBundlePath` (default + served + `CriticalMaxAge`). |
| TM-08 | "single-host package still has non-digest images" | All 5 images in `package/adamance/docker-compose.yml` are `@sha256:`-pinned. |
| TM-14 | "krb5 lifetime not verified in code" | `hostconfig/sssd.go` sets `krb5_lifetime=8h`, `krb5_renewable_lifetime=24h`, `krb5_renew_interval=2h`. |
| TM-17/18/21/22 | CI build / audit→Wazuh / server TLS1.3 / argon2 "not verified" | All present: `.github/workflows/policies-build.yml`; `src/common/audit/wazuh.go` (`WazuhEmitter`); server `MinVersion: VersionTLS13`; password hashing delegated to FreeIPA (no bcrypt/scrypt/argon2 in `src/`). |

**Real gaps found this pass → FIXED (2026-07-11):**
- **TM-23 residual (crypto baseline):** `src/client-agent/internal/enroll/join.go` set `MinVersion:
  tls.VersionTLS12` on all three join-bootstrap TLS configs (CA-file, fingerprint-pin, `--insecure`),
  below the TLS 1.3 baseline the rest of the stack enforces. **Fixed → `tls.VersionTLS13`** (the gateway
  edge is TLS 1.3-capable; the other agent paths already used 1.3). The table's "no remaining
  `VersionTLS12` in `src/`" claim is now actually true.
- **Account lockout / credential stuffing (was "❓ NOT FOUND"):** the Keycloak realm had **no
  brute-force protection**. **Fixed**; the production realm template
  (`deploy/setup/keycloak/realm-adamance.json.tmpl`) now sets `bruteForceProtected:true`,
  `failureFactor:10`, temporary lockout (`permanentLockout:false`, `maxFailureWaitSeconds:900`). (Dev
  provisions its realm separately and additionally has the OIDC 5/min per-IP rate limit.)

**Confirmed DEFERRED-BY-DESIGN for V1 (genuine, documented, acceptable, not "broken"):**
- **TM-09 air-gapped / no-GitHub installer**; being CLOSED right now: the gateway now serves the
  agent binary itself (fail-closed Ed25519), replacing GitHub Releases (see the turnkey-install work).
- **TM-11 residual** (HSM/Vault-Transit signer → V1.5), **TM-20** (operator↔control-plane pivot: N/A on
  single-host), **TM-25** (per-tenant IPA isolation → V2), **TM-12** (Wazuh FIM of the agent's own
  logs → V1.5; Wazuh is stub in V1), **TM-13** (central sudo-event audit = host-OS config), B1 (public
  WAF/allowlist → V1.5; V1 is private/VPN-only, SCOPE-10). Network exposure of FreeIPA LDAPS/Kerberos
  ports is REQUIRED for managed-host SSSD and is bounded by the VPN perimeter (SCOPE-10).

**Still genuinely open (low / informational):** TM-15 CIS-policy default-deny review (compliance-suite
audit, distinct from the authz default-deny review which IS done); TM-01/02/03/05 architecture
open-decisions (HA model, bundle distribution, audit retention, MFA recovery; track to closure).

## Purpose

This document defines **what adamance defends against and why.** Every security decision elsewhere in the project should
trace back to a threat described here. If a control doesn't address a documented threat, it's probably ceremony. If a
threat has no control, it's a gap and must be tracked.

This is the source of truth for security requirements. Anything in `docker-compose.yml`, the API code, the client agent,
or the UI that contradicts this document is a bug.

## Scope

**In scope:**

- The adamance control plane (FreeIPA, OPA, Wazuh, API gateway, admin UI)
- The client agent and its trust relationship with the control plane
- User authentication and session flows
- Host enrollment and lifecycle (join, rekey, decommission)
- Policy distribution and evaluation

**Out of scope (initial release):**

- Workload-level identity for containers (SPIFFE/SPIRE territory)
- Physical security of servers and operator workstations
- Endpoint hardening of managed Linux hosts beyond what we ship in default policy (host owners are responsible; we
  provide hooks)
- Defense against a hostile nation-state or a compromised hardware supply chain

## Assets

Ranked by blast radius if compromised:

| Rank | Asset                                                | Impact if compromised                                                                 |
| ---- | ---------------------------------------------------- | ------------------------------------------------------------------------------------- |
| 1    | KDC master key / KRB principal database              | Silent forgery of Kerberos tickets across the fleet; total identity compromise        |
| 2    | CA private key (Dogtag)                              | Ability to issue trusted client/server certificates impersonating any host or service |
| 3    | SSH CA private key (step-ca, K-05)                   | Issue SSH certificates impersonating any user to any host (compromise rated catastrophic); separate chain from Dogtag per CRYPTO-07 |
| 4    | Directory admin credentials (`cn=Directory Manager`) | Create/escalate accounts, modify group membership, disable policy                     |
| 5    | OPA bundle signing key                               | Push arbitrary policy to every managed host (e.g. allow any SSH) ⚠️ Corrected 2026-09-26 (external review), measured at `27679898d`: the same key verifies agent binaries (`configs/api-gateway/api-gateway.dev.yml:277`, "one trust root for both"), so it also pushes an arbitrary agent binary to every managed host, which is root on the fleet. Either it ranks with the SSH CA key or bundles and binaries get separate keys with separate custody; that choice is owed. |
| 6    | API gateway JWT signing key                          | Forge admin sessions without touching the directory                                   |
| 7    | Postgres transactional store (MFA evidence, refresh tokens, enrollment tokens; DATA-02) | Forge fresh-MFA state to bypass every step-up gate, exfiltrate refresh/enrollment token hashes, replay enrollment |
| 8    | Wazuh agent enrollment key                           | Log spoofing, alert suppression, blind the SIEM                                       |
| 9    | Operator MFA recovery codes                          | Bypass MFA on operator accounts                                                       |
| 10   | OpenBao unseal shares and root/recovery token        | ⭐ Added 2026-09-04. Unseals the store holding several of the rows above, so it inherits their blast radius. Split across people, never on the store's own host, never inside the deployment's own backup. ⚠️ Noted 2026-09-26 (external review): an asset that inherits the blast radius of the rows it unseals cannot rank below them. Its rank is owed once it is stated which of assets 1 to 7 live in OpenBao. |
| 11   | Audit chain HMAC key                                 | ⭐ **Added 2026-09-05, and its absence was the defect.** Hold it and you rewrite history from any point, re-chain it, and every integrity check passes. The subsystem document has ranked it #1 since it was written; this master inventory never listed it at all, which is why the row below dangled — it said "rank 10 collapses into one compromise" while rank 10 was a different asset entirely. See [`THREAT_MODEL_audit_anchoring.md`](THREAT_MODEL_audit_anchoring.md). |
| 11=  | Anchor signing key                                   | ⭐ Added 2026-09-04. Forge an off-box anchor and the only witness to a rewritten chain agrees with the rewrite. 🔴 **Measured the same day: this is currently the audit chain's own symmetric key, so it is not a separate asset at all and it collapses into the row above.** ⚠️ **Corrected 2026-09-05: this row was ranked 12 and pointed at "rank 10", which named the audit logs rather than the chain key it meant. The key it collapses into is now listed, and both share rank 11.** See [`THREAT_MODEL_audit_anchoring.md`](THREAT_MODEL_audit_anchoring.md). ⚠️ Corrected 2026-09-26 (external review): "the only witness to a rewritten chain agrees with the rewrite" holds going forward only. Anchors already delivered to an append-only destination stand (TM-31, corrected 2026-09-05). |
| 12   | Stored session recordings                            | ⭐ Added 2026-09-04. Everything anyone typed in a privileged session, in bulk. Ranked here and not only in the subsystem document because the disclosure needs no other asset first. |
| 13   | Audit logs                                           | Destruction or tampering hides any of the above. ⚠️ **Renumbered 2026-09-05: this row was numbered 10 and printed last, so the table ran 9, 11, 12, 13, 10 and the number no longer meant anything. The whole column is now monotonic.** |

## Trust boundaries

| From                          | To                          | Boundary type              | Authentication                    | Channel                           |
| ----------------------------- | --------------------------- | -------------------------- | --------------------------------- | --------------------------------- |
| User browser                  | Reverse proxy / UI          | Public ↔ edge              | TLS server cert                   | TLS 1.3                           |
| Admin UI                      | API gateway                 | Edge ↔ control plane       | OIDC bearer JWT + CSRF token      | TLS 1.3                           |
| API gateway                   | FreeIPA                     | Intra-control-plane        | Service principal + GSSAPI        | LDAPS / Kerberos                  |
| API gateway                   | OPA                         | Intra-control-plane        | mTLS (SPIFFE-style SVIDs)         | HTTPS                             |
| API gateway                   | Wazuh API                   | Intra-control-plane        | mTLS + scoped API key             | HTTPS                             |
| API gateway                   | Postgres                    | Intra-control-plane        | DB credential (Vault-issued)      | TLS (local socket in single-host) |
| Managed host (SSSD)           | FreeIPA                     | Untrusted ↔ control plane  | Host keytab                       | Kerberos / LDAPS                  |
| Managed host (Wazuh agent)    | Wazuh manager               | Untrusted ↔ control plane  | Pre-shared agent key, mutual auth | Wazuh proto (encrypted)           |
| Managed host (adamance agent) | OPA bundle endpoint         | Untrusted ↔ control plane  | Signed bundles + mTLS host cert   | HTTPS                             |
| Operator workstation          | Control plane (break-glass) | Privileged ↔ control plane | Hardware token + audited bastion  | SSH over WireGuard                |
| Break-glass account (console) | Control plane (JIT elevation, no approver) | Privileged ↔ control plane | Sealed password + second factor through Keycloak and the edge; fresh MFA (≤ 300 s); live membership of `super-admins`. Pages every super-admin; cannot approve anyone | TLS 1.3 |
| API gateway                   | OpenBao / secrets store     | Intra-control-plane        | AppRole or Kubernetes auth        | TLS                               |
| Every component               | Its time source             | Untrusted ↔ everything     | ⚠️ none stated                    | NTP, unauthenticated              |

## Adversaries

We design explicitly against four threat actor profiles.

### A1: External unauthenticated attacker

**Access:** network reachability to whatever the deployment exposes. **Goal:** any foothold. **Capability:**
opportunistic port scanning, public exploits, credential stuffing, phishing. **Not capable of:** zero-day exploits in
upstream components; cryptographic breaks.

### A2: Compromised managed host

**Access:** root on a host that was enrolled legitimately. **Goal:** lateral movement, persistence, privilege escalation
across the fleet. **Capability:** full control of a Linux box including its host keytab, the local SSSD cache, and any
user tickets that touch the host. **Realistic vector:** unpatched application, supply-chain compromise, stolen developer
SSH key.

### A3: Malicious or compromised user

**Access:** valid credentials for some user account (could be a low-privilege user, could be an operator). **Goal:**
access beyond their authorization, exfiltration, or destruction. **Capability:** whatever the account legitimately can
do; social engineering of other users; abuse of any policy gap.

### A4: Insider with control plane access

**Access:** legitimate operator account on one or more control-plane components. **Goal:** usually mistakes (most
common), occasionally malicious. **Capability:** depends on operator role; in the worst case, root on the FreeIPA host.

⭐ **Split into capability profiles 2026-09-05, because one label was hiding five adversaries.** "A4" was being
used to mean anything from a logged-in operator to root on the control-plane host, and rows drifted between them
mid-sentence — sometimes quietly picking the weakest reading so a control could be said to defeat A4, and at least
once picking a *stronger* one than this section defines so a threat would land (TM-41 said "A4 is defined here as
an insider who holds the database", which is not what the paragraph above says). A control that "defeats A4" now
has to say which profile.

⛔ **These are capability profiles, not a privilege ladder.** They overlap and compose; A4c does not contain A4b.
The **goal** axis above is orthogonal and still applies to every one of them — most real A4 events are mistakes,
which is why dual control and undo matter as much as detection.

| Profile | Capability | What it changes |
| --- | --- | --- |
| **A4a** | Authenticated adamance operator, acting through the console and the API | Bounded by policy and by dual control. This is the profile most controls in this document actually address. |
| **A4b** | The gateway process itself is compromised | Every record the gateway produces is now the attacker's, including the audit chain, the authorisation decision it reports and the actor it names. "Make the gateway the only mutation path" does nothing here. See TM-42. |
| **A4c** | Database administrator or `postgres` superuser | Mutates state directly and is above every table trigger. Native database audit shipped off-box may catch it; local logs on the same host will not. |
| **A4d** | FreeIPA, Keycloak or OPA administrator | Changes identity, tokens or policy at the source, without touching adamance at all. See TM-41. |
| **A4e** | Root on a control-plane host | Everything above, plus the keys, plus the logs that would show it. This is the profile the audit-anchoring model is written against. |

⚠️ **Subsystem models must reference these profiles, not restate them.** Local redefinitions are how the drift
started — "holds the database, probably holds the key" in one document, "holds the signing key and the stored
recordings" in another, "a domain admin in waiting" in a third. Where a subsystem needs a narrower adversary it
names the profile and says what it adds.

## Attack vectors and required controls

Each row is a documented threat plus the control(s) that address it. The control column drives implementation
requirements; if it's not built, the threat is open.

### Initial access (primarily A1)

| Vector                                        | Required control                                                                                                                                                                  |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Exposed admin UI / API on the public internet | V1 is private/VPN-only (SCOPE-10, Locked); bind to the private network / VPN (e.g. WireGuard, Tailscale); no public internet exposure. The public-exposure path (reverse proxy with WAF, IP allowlist) is **V1.5+** forward-looking design, not a V1 path. |
| Credential stuffing against admin UI | MFA required for **all** admin accounts (FreeIPA OTP or WebAuthn). Rate limit on `/oauth/token`. Account lockout after N failed attempts with exponential backoff. ⭐ Added 2026-09-26 (external review): the deployment-wide `second_factor_required` opt-out is itself a governed change: dual-controlled, gated on fresh MFA, audited, and shown on the compliance surface as a failing control for as long as it is off. It never applies to a non-human subject. Measured at `27679898d`: `check_user_with_mfa_stepup` refuses any subject that is not a human user before the opt-out is consulted (`policies/api/authz.rego:2601`), and both opt-out clauses themselves require `is_human_user_subject` (`:2670`, `:2702`). **Status of the governance clause: NOT MEASURED.** |
| Phishing of admin session cookie              | Short JWT lifetime (≤15m), refresh tokens bound to IP and User-Agent, MFA step-up required for sensitive operations (user creation, policy change, machine enrollment).           |
| A stolen refresh token is exchanged before its owner uses it, and the thief keeps the successor | ⭐ Added 2026-09-26 (external review). Single use stops the owner's later request and does not stop the thief who got there first. Refresh tokens stay single-use and bound to IP and User-Agent; rotation is atomic across replicas and records a token family; presenting an already-consumed token revokes every live descendant in its family, and the sessions derived from them, inside the revocation-convergence bound. A retry accommodation may return only the result already issued to the same bound request and never mints a second successor. Refresh never extends the family's absolute lifetime and never manufactures fresh MFA evidence. **Status: NOT MEASURED.** |
| Vulnerable upstream container image           | Pin all images by digest, not tag. Weekly Trivy scan in CI with a blocking severity threshold. Documented monthly patch cadence with emergency channel for CVEs ≥ 9.0.            |
| The browser-facing OIDC flow is attacked instead of the password | ⭐ Added 2026-09-04. `state` and PKCE on every authorization request, `nonce` validated on the ID token, exact-match redirect URIs with no wildcard or prefix match, an authorization code that can be exchanged once, and a session identifier rotated on every privilege change. **Status: PARTIAL**, and ⚠️ **corrected 2026-09-04: the flow was never written down here, which is not the same as never built.** Measured: PKCE, `state` and `nonce` are all built and the nonce is asserted against the ID token on callback — `src/api-gateway/internal/handlers/auth/keycloak.go:342` builds the authorization URL with `code_challenge`, and the state cookie is HMAC-signed over the state, the code verifier, the CLI redirect, the nonce and the expiry together (`:194`) so a captured cookie yields neither verifier nor nonce. Unstated and unverified here: exact-match redirect URIs, single-exchange enforcement on the code, and session-identifier rotation on privilege change. ⚠️ Reconciled 2026-09-27: the published and maintained copies had diverged here, and the other version also read "**Status: NOT MODELLED.** The rows above cover the credential and the cookie; the flow that mints the cookie was never written down.", and marked it **NOT MODELLED**. |
| A validly signed token is accepted by a consumer it was not issued for | ⭐ Added 2026-09-26 (external review). Every token consumer holds an explicit allowlist of issuers, audiences, token classes and signing keys, and validation binds the key to the configured issuer. An ID token, an access token, a refresh token, an approval proof and a service credential are not interchangeable, and a field inside an untrusted token can never select the issuer, the key source or the validation policy. A subject is qualified by the authority that issued it, and a token minted for another client or another deployment is refused. **Status: NOT MEASURED.** |
| Content the console renders is attacker-supplied | ⭐ Added 2026-09-04. Hostnames, group names, approval reasons, audit fields, policy names and replayed transcript output all reach the console and all originate outside it. Output encoding at render, a CSP that forbids inline script, no CORS origin beyond the console's own. **Status: PARTIAL**, and ⚠️ **corrected 2026-09-04.** A CSP forbidding inline script is served by the reverse proxy in front of the console — `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'` at `configs/caddy/Caddyfile.setup:58` and `deploy/dev/caddy/Caddyfile:39`. Output encoding at render and the CORS position are stated nowhere. A stored script in a hostname runs with an operator's session and needs no phishing to get there. ⚠️ Reconciled 2026-09-27: the published and maintained copies had diverged here, and the other version marked it **NOT MODELLED**. |
| An authorised field becomes syntax in a non-browser interpreter | ⭐ Added 2026-09-26 (external review). The row above covers browsers. Every other place caller- or directory-supplied data is rendered into a query, a command argument or a configuration file (LDAP filters, sudoers, `sshd` and `sssd` drop-ins, systemd units, FreeRADIUS and Samba configuration) uses that destination's typed API or grammar-correct encoding, so a value cannot introduce a directive, an option, a record, an include path or executable content. Resolved secret values are validated as well as their references. Generated security configuration is parsed and validated before an atomic install, and a rejected value leaves the previous valid file in place. **Status: NOT MEASURED.** |
| An authenticated caller changes an identifier and reaches another subject's object | ⭐ Added 2026-09-04. Object-level authorization on every route that takes an identifier, decided against the object rather than the route, and request bodies bound to an explicit field allowlist so a client cannot set a field the handler never meant to accept. **Status: NOT MODELLED.** |
| Direct exposure of LDAP/Kerberos ports        | Only the reverse proxy is in the edge zone. LDAPS and Kerberos are not reachable from outside the control plane subnet. ⚖️ **The 2026-09-02 correction on this row is withdrawn, 2026-09-15.** It recorded that the shipped HA compose contradicted this control by publishing seven directory and Kerberos ports in short form; the overlay was rewritten on 2026-09-05 and the contradiction is gone. Re-measured 2026-09-15: the HA overlay's only publication is `deploy/docker-compose.ha.yml`:376, which binds `${ADAMANCE_HA_LB_BIND:-127.0.0.1}`, and both replicas carry `ports: !reset []` at :123 and :144 — the composed HA project publishes nothing on all interfaces, and `src/api-gateway/internal/deployspec/ha_topology_test.go` guards the relapse. The single-host package was never affected. |
| A caller claims an unowned installation, or reopens its bootstrap authority | ⭐ Added 2026-09-26 (external review). Before any administrator, break-glass identity or trust root exists, setup requires a single-use, high-entropy capability specific to this installation, delivered through a channel the deployment owner controls (the installer's own terminal, not the network). Being the first caller on the network confers nothing. Consumption is atomic and bound to this installation and this setup session. Completing setup closes the bootstrap interface for good: a restart, a resumed partial install or an upgrade cannot reopen it, and reinitialising needs separately authenticated recovery authority and is recorded. **Status: NOT MEASURED.** |

### Enrollment (primarily A1, A2)

| Vector                               | Required control                                                                                                                                                                                                 |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unauthorized host joining the domain | Enrollment requires a **one-time scoped token** issued by an authenticated admin, bound to an expected hostname, expiring within 24 hours. No anonymous enrollment. No `1515/authd` exposed without prior token. |
| MITM of the install script | Install artifact is served over TLS only, from a pinned hostname, with a published SHA-256 checksum. Production deployments distribute via an internal package repository, not `curl \| bash`. ⭐ Strengthened 2026-09-26 (external review): the agent binary the served script fetches carries a detached Ed25519 signature the host verifies, before the binary is executable, against the release public key delivered out of band with the enrolment token and the CA fingerprint. A checksum minted by the serving gateway is transport integrity only and never satisfies this row. **Status: NOT_BUILT** for that clause, measured at `27679898d`: `verify_download` (`src/api-gateway/internal/handlers/installers/agent_install.sh:125`) compares a SHA-256 and checks no signature; the only Ed25519 check is the gateway's own (`:117`). |
| Replay of an enrollment token        | Tokens are single-use and consumed atomically by the API. Token use is logged with the source IP and resulting host principal.                                                                                   |
| Hostname spoofing during enrollment  | The enrolling host must present a CSR for the hostname declared in the token. The CA refuses to sign for a name not in the token. ⭐ Extended 2026-09-04: the match is against the SAN and not the CN alone, an extra SAN entry in the CSR is a refusal rather than an ignore, and the requester proves possession of the private key. **Status: PARTIAL**, and ⚠️ **corrected the same day: two of those three clauses are built.** `machines.ParseCSRIdentity` verifies the CSR self-signature (`src/api-gateway/internal/machines/cert.go:27`), which is proof of possession, and `machines.CSRNamesHost` (`:57`) matches the CN **or any DNS SAN**. ⭐ **Corrected again 2026-09-14: the third clause is now MET and all three hold.** `machines.CSRIdentity.BindsOnlyTo` requires the request to name this host and NOTHING else — every DNS SAN must equal the hostname, a non-empty CN must too, and an IP, email or URI SAN is refused outright. Those three name types were previously parsed and DISCARDED UNREAD, so a request naming an arbitrary IP reached the CA with nothing having looked at it. ⚠️ Two tests actively mandated the old behaviour and were rewritten; four planted defects now fail. ⛔ FreeIPA's own profile is still an unmeasured second line of defence — that clause is unchanged. **Status: BUILT.** |
| The enrolling host trusts whichever CA answers first | ⭐ Added 2026-09-04. First contact is the weakest moment in the lifecycle and it is the moment the trust root gets decided. The agent pins the CA by a fingerprint delivered out of band with the token rather than trusting the first certificate it is shown, and ⚠️ **corrected 2026-09-26 (external review), because the clause as written could never be met**: it read "and the gateway refuses to complete an `--insecure` bootstrap for a production token", and a server cannot see whether a TLS client verified its certificate. The achievable form, stronger for everything the gateway controls: the enrolment token carries the control plane's CA fingerprint, the agent refuses to bootstrap without a pinned fingerprint or a CA file, `--insecure` is compiled out of production agent builds, the gateway refuses to issue a production token that carries no fingerprint, and the served install one-liner never contains an insecure mode. **Status: PARTIAL**, all three bootstrap modes exist in `src/client-agent/internal/enroll/join.go` and nothing refuses the weak one. |
| An enrollment token is guessed, or read out of a log or a shell history | ⭐ Added 2026-09-04. At least 128 bits from a CSPRNG, stored hashed, never logged in full, and never embedded in the served install command: the installer reads it from a prompt or from a `0600` file the operator places, and the console shows it once. (⚠️ Corrected 2026-09-26, external review: this read "and delivered by a channel that is not the one carrying the install command wherever that is possible", and a control hedged with "wherever that is possible" cannot be shown unmet.) A `curl \| bash` line with its own token in it lands the credential in two shell histories and a proxy log. **Status: PARTIAL**, single-use and expiry are built, entropy and handling are unstated. |
| A host is cloned, or re-enrolls under a name that already exists | ⭐ Added 2026-09-04. Enrollment for a name that is already active is refused rather than joined, unless the prior host was explicitly decommissioned. A VM image captured after enrollment carries a host key and a certificate, so two machines hold one identity and no audit trail can separate them. Decommission and rekey are lifecycle steps, not a manual tidy-up. **Status: PARTIAL** (⚠️ corrected 2026-09-26, external review: this read "**Status: NOT MODELLED.**" while TM-34 had measured re-enrolment under an active name as refused, `src/api-gateway/internal/enrollment/handler.go:695-713`). Detecting a cloned identity, two live holders of one certificate or keytab, is not measured. |
| A decommissioned host keeps working | ⭐ Added 2026-09-04. Decommission revokes the host certificate, disables the host principal, invalidates the keytab and drops the host from bundle scope, inside the bound stated in the revocation-convergence row below. **Status: PARTIAL** (⚠️ corrected 2026-09-26, external review: this read "**Status: NOT MODELLED.**" while TM-40 had measured every host-mTLS operation refused after decommission, `src/api-gateway/internal/middleware/hostlifecycle.go`). Revocation at the CA, keytab invalidation, bundle scope and the convergence bound are not measured. |

### Lateral movement (primarily A2)

| Vector                                                           | Required control                                                                                                                                                                        |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Compromised host uses its keytab to authenticate as another host | Host keytabs grant only the host's own identity. No transitive trust. User SSH uses **ephemeral certificates** issued by the internal SSH CA (step-ca, ARCH-05); host credentials are not accepted for user-initiated SSH. |
| A certificate issued for one class of identity is accepted as another | ⭐ Added 2026-09-26 (external review). Every certificate-authenticated endpoint checks the issuing authority, the permitted certificate profile, key usage and extended key usage, the identity namespace and the current lifecycle state for the one class of identity it accepts. Host, user and control-plane service certificates are not interchangeable because they share a root. Issuance and renewal take the identity class and the permitted names from enrolment state, never from fields the requester chose. **Status: NOT MEASURED.** |
| Theft or misuse of the SSH CA signing key (issue rogue user certs) | SSH CA (step-ca, K-05) is a separate trust chain from Dogtag (CRYPTO-07); signing key home is Vault Transit / sealed offline file. Certs are short-lived; revocation by KRL (⚠️ corrected 2026-09-26: this read "revocation, CRL distribution"; `sshd` consumes a KRL, not an X.509 CRL, see the KRL row below) and CA-key-compromise threats are enumerated in the SSH CA design rather than here. |
| Compromised host modifies its own audit logs to hide activity    | ⚠️ **Corrected 2026-09-02: this row credited Wazuh FIM, which is not wired.** No adamance code emits a FIM watchlist (TM-12 below), and Wazuh is an optional module nothing gates on. The control that does hold is central: privileged actions land in the HMAC-SHA256 chain on the control plane, not on the host, and an anchor of the chain head is published on a timer. ⚠️ **Corrected 2026-09-05: this read "a signed anchor ... leaves the box", and both halves flatter it.** "Signed" means HMAC'd under the chain's own key, which is not a signature anybody outside the box can check; and it leaves the box only as far as Wazuh, which ships inside this same stack. See TMA2-07 and TMA2-11. 🔴 **Measured 2026-09-04: that anchor is signed with the chain's own symmetric key, so it does not witness anyone who holds that key.** Against a compromised host this row still holds, because the host does not have the key. ⚖️ **OPERATOR REFUTED 2026-09-04, propagated here 2026-09-05. This row ended "Against A4 it does not", which is the flat conclusion the maintainer overturned that day and which TM-31 and TMA2-06 both withdrew. It was left standing here when they were corrected.** Against A4 it holds for whatever had already reached a destination the control plane cannot rewrite, and fails for everything after the key is taken. The correction was propagated to TM-31 and not to this row, which is the exact failure the reading rule at the top of this document exists to prevent. See TM-31. See [`THREAT_MODEL_audit_anchoring.md`](THREAT_MODEL_audit_anchoring.md). Where an operator has installed the Wazuh agent, real-time forwarding is a second copy and not the primary control. |
| Compromised host pulls sensitive policies it shouldn't see | 🔴 **NOT MITIGATED, corrected 2026-08-31.** Bundle requests are authenticated with the host certificate, and that is ALL that is checked. Bundles are **not** scoped per host group: every enrolled host receives byte-identical bundles. See the as-built note below. ⭐ Required control restated 2026-09-26 (external review), because this cell had become only a status: OPA bundles are scoped per host group. A host receives only the policy and data that concern it, fleet-wide host maps (`host_group.json`, `host_tiers.json`) never ship in a bundle every host can read, and bundle requests are authenticated with the host certificate and admitted only for a currently enrolled host. Whether that means per-caller bundles or stripping the maps is the open ruling recorded at TMS-13. |
| A host whose enrollment was revoked keeps being served | 🔴 **NOT HELD, measured 2026-09-04.** Four certificate-authenticated routes check the certificate and never ask whether the host is still enrolled, so revoking a host removes it from the console and not from the API. One of the four hands out every RADIUS shared secret. A valid certificate is the entire boundary on those routes, which makes revocation a display change rather than a control, and short certificate lifetimes are the only thing bounding it. Required: enrollment status is checked on every certificate-authenticated route, not only at issue, and revocation takes effect inside the bound in the revocation-convergence row below. See TM-40 and [`THREAT_MODEL_network_modules.md`](THREAT_MODEL_network_modules.md). |
| Compromised host abuses its sudo rights to escalate | sudo rules are scoped narrowly (specific commands, not `ALL=(ALL)`). Sudo invocations are audit-logged centrally and trigger alerts on anomaly. ⭐ Strengthened 2026-09-26 (external review): scoping constrains the effective operation, not only the executable name. The authorisation boundary includes the ownership of the executable and its dependencies, the arguments, the environment, the working directory, input files and any shell, plugin or subprocess capability. A command that can give unrestricted privileged execution is treated as unrestricted privilege and gets that approval tier, and the executing user can replace neither the permitted executable nor its privileged dependencies. Sudo rules the product seeds by default are visible in the console before they reach FreeIPA, and none is seeded that allows raw disk writes, secure deletion or a database drop. |
| An SSH certificate is revoked and `sshd` never hears about it | ⭐ Added 2026-09-04, and ⚠️ **corrected the same day against the tree, because the row as first drafted said the KRL path was not built and all three halves of it are.** `sshd` consumes a KRL or `RevokedKeys`, not an X.509 CRL. The gateway builds a real KRL (`sshca.BuildKRL` at `src/api-gateway/internal/handlers/sshca/crl.go:140`); the agent polls it, writes `/var/lib/adamance/ssh_krl.pem` and SIGHUPs sshd (`src/client-agent/internal/crl/fetcher.go`), with ETag and a monotonic `X-KRL-Generation` against rollback; and the managed sshd drop-ins set `RevokedKeys` to that path (`deploy/dev/prod-host/entrypoint.sh:249`, `deploy/dev/bastion/sshd_bastion.conf:16`). What is required and absent is the **bound**: the poll interval defaults to 60 minutes (`src/client-agent/internal/crl/fetcher.go:94`), so a revoked certificate is honoured for up to an hour by default and nothing measures the real figure on a managed host. The KRL is also unsigned, so its integrity rests entirely on the mTLS fetch. Short certificate lifetimes bound the damage and are not revocation. **Status: PARTIAL**, built end to end and unmeasured. ⚠️ Reconciled 2026-09-27: the published and maintained copies had diverged here, and the other version also read "⭐ Added 2026-09-04. `sshd` consumes a KRL or `RevokedKeys`, not an X.509 CRL, so the revocation path has to produce, distribute and load the artifact `sshd` actually reads, with a measured convergence bound." and "The CRL endpoint at `src/api-gateway/internal/handlers/sshca/crl.go` is not on its own evidence that this holds.", and marked it **OPEN, unverified**. |
| A user reaches a server that is not the managed host they named | ⭐ Added 2026-09-26 (external review). User certificates prove the user to the host; nothing here yet proves the host to the user. Every adamance SSH client authenticates the destination against a host trust root provisioned independently of that connection (the SSH host CA, or an approved host-key pin), checks that the authenticated host identity is the target that was requested, and applies host-certificate validity and revocation. Managed access never falls back silently to accepting an unknown or changed host key, host-key rotation keeps the target identity through an authenticated transition, and agent and credential forwarding are off unless explicitly authorised for that destination. **Status: NOT MEASURED.** |
| A privileged mutation lands and its audit entry does not | ⭐ Added 2026-09-04. A valid hash chain proves what was written was not altered. It says nothing about what was never written, and a missing entry reads exactly like an action that never happened. FreeIPA, Keycloak, Postgres and OPA cannot share one transaction, so: intent recorded before the mutation is attempted, outcome recorded after, an outcome nobody could confirm stored as an explicit unconfirmed state rather than dropped, reconciliation to resolve those states, and an audit append that fails takes the operation down with it. **Status: NOT MODELLED.** |
| Stolen user TGT used from another host                           | Tickets are address-bound on managed hosts: the agent-written `krb5.conf` requests addressed tickets and does not mark them forwardable unless the host group opts in with a recorded reason, and the KDC refuses a TGT presented from an address the ticket does not list. (⚠️ Corrected 2026-09-26, external review: this read "Tickets are bound to addresses where possible.", and a control hedged with "where possible" cannot be shown unmet. If address binding proves unworkable behind NAT, that is a ruling to record on this row, not a hedge inside it.) Short ticket lifetime (8h default per SSSD `krb5_lifetime`; 1h target for admin principals, enforced via per-principal KDC policy `max_life`). Renewal requires re-auth past max renewable lifetime (24h). |

### Policy bypass (primarily A3)

| Vector                                                            | Required control                                                                                                                                                                              |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| User exploits a gap in a policy that wasn't `default deny`        | All OPA decision documents and all FreeIPA HBAC rules are default-deny. Explicit allows only. Verified by policy unit tests in CI.                                                            |
| A local process forges the inputs to a host's policy decision, or calls the agent's privileged operations directly | ⭐ Added 2026-09-26 (external review). Local decision and mutation interfaces authenticate the calling process and authorise each operation. Subject identity and process credentials come from the kernel; groups, grants, MFA evidence and the policy revision come from authenticated authorities, and no caller can supply or override those facts. Being able to ask OPA a question never confers write access to its policy or data. Privileged execution is bound to the authenticated caller, the target and the exact operation that was authorised, and no second local interface reaches the same effect without that decision. **Status: NOT MEASURED.** |
| User races between policy update and enforcement | Local OPA decisions on the host. Bundle TTL ≤ 60s for security-critical policies. Push-on-change via webhook for the highest-impact policies (SSH, sudo, admin group membership). ⚠️ Corrected 2026-09-26 (external review): the set this row names (SSH, sudo, admin-group membership) is not the set the critical bundle carries, which is `policies/firewall` and `policies/lib/decision.rego` (TM-16). Required: the policies that decide SSH access, sudo (at whichever layer serves it, so the FreeIPA sudo sync interval counts), firewall and admin-group membership are served in a bundle whose max-age is at most 60 seconds and which every enrolled agent fetches on a ticker of at most 60 seconds, with push-on-change for the same set, and a test fails when a named policy is missing from that bundle. |
| An old security-critical policy is kept in force by replay, a 304 or a restored cache | ⭐ Added 2026-09-26 (external review). An HTTP `max-age` bounds a cache, not the age of an authorisation. Local enforcement holds a security-critical policy as a lease of at most 60 seconds, bound to an authenticated policy generation and to an authoritative issue or renewal time. Receiving the same bytes again, a 304, a restart or a restored local cache never renews the lease; renewal needs fresh authenticated authority that reflects current revocations. An expired or unverifiable lease fails closed, and the host persists the generation floor that stops an older generation becoming current again. **Status: NOT MEASURED.** |
| Policy change introduces a vulnerability that ships before review | Policy changes go through git → CI (rego unit tests, opa eval against fixtures) → review (one approver minimum; two for policies touching admin groups or root access) → signed bundle build. |
| A host enforces a mixture of individually valid policy generations | ⭐ Added 2026-09-26 (external review). A publication names the complete compatible set: decision code, authorisation data and the host configuration generated from them. A host stages and validates the whole set before activating it, and each decision uses exactly one generation. Where two enforcement systems cannot switch atomically, the transition has a stated order that can never grant access the approved change did not grant, and affected operations are refused while the state is inconsistent. Crash recovery never silently combines an old generation with a new one. **Status: NOT MEASURED.** |

### Control plane compromise (primarily A4)

| Vector                                                | Required control                                                                                                                                                                                   |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Operator with API access silently escalates a user | All write operations to FreeIPA and OPA are logged to Wazuh tagged with the operator's identity. Logs are write-only from the operator's perspective (separate retention bucket with object lock). ⭐ Added 2026-09-26 (external review): the system of record is the hash chain, and a chain append that fails refuses the operation (the cross-cutting rows below). Delivery to the SIEM is a second copy: a failed delivery is a reported degraded state, never a silent stdout-only default, and an install with no SIEM configured shows the audit copy as absent on the compliance surface. |
| Compromised operator account changes policy | Sensitive operations require fresh MFA (step-up within last 5 minutes). High-impact policy changes (anything affecting `admins`, `wheel`, or root SSH) require a second approver via the UI. ⚠️ **Disambiguated 2026-09-05: "second approver" is used in two incompatible senses in this document and a reader hits both.** Here it means a second *person* — the requester plus one approver — which is what the default configuration enforces. In `require_approval.rego` the flag named `second_approver` means a second *approver on top of the first*, so setting it true requires three people. The default is `false`. Whether high-impact policies override it to `true` is not established in the tree and is not claimed here. ⚠️ Clarified 2026-09-26 (external review): this row says "a second approver", the policy-change row below says "two for policies touching admin groups or root access", and the 2026-09-02 correction on TMS-20 records that the built default is one approver distinct from the requester. The requirement is the stronger reading, selected by content: every policy publish needs at least one approver distinct from the requester, and a publish whose content touches `admins`, `wheel`, `super-admins`, root SSH, sudo rules or the approval matrix needs two, chosen by what the change touches and not by a deployment-wide toggle. `second_approver` may raise the count for everything and never lowers it for those. **Status: PARTIAL**: approver counting and no-self-approval are built; content-selected counts are not measured. |
| Backup tampering                                      | Backups are signed and encrypted with a key that no operator account holds. Restore requires presenting the offline key.                                                                           |
| An approval is replayed, or granted for one thing and spent on another | ⭐ Added 2026-09-04. "A distinct approver approved something" is not enough. An approval binds to the normalized operation, the requester, the target, a hash of the parameters or content, the policy revision in force, an expiry and a single-use nonce, and altering any of them voids it. Without that, A is approved and B is executed, or A is mutated after approval and before use. The same binding applies to policy publication, agent escalation requests, break-glass, restore, Samba domain plans, identity-source and RADIUS-client enrolment, and changes to the approval matrix itself (⭐ list extended 2026-09-26, external review; it read "policy publication, agent escalation requests, break-glass and restore"). **Status: PARTIAL.** The approver-count and no-self-approval half is built in `policies/governance/require_approval.rego`, and the policy-publish path does bind to what it approved — `approval.Approval` carries `ChangeScope`, `BundleDigest` and `ExpiresAt` (`src/api-gateway/internal/storage/approval/store.go:92`). Absent everywhere: a single-use nonce, the policy revision in force, and a normalized operation-plus-parameter hash for any approval that is not a bundle. ⚠️ Reconciled 2026-09-27: the published and maintained copies had diverged here, and the other version also read "**Status: NOT MODELLED**, the approver-count and no-self-approval half is built in `policies/governance/require_approval.rego`, the binding half is not.", and marked it **NOT MODELLED**. |
| The secrets store is unsealed, dumped or restored by the wrong person | ⭐ Added 2026-09-04. OpenBao is a trust boundary and was not described as one anywhere. Unseal shares and root or recovery tokens split across people, never resident on the store's own host, never inside the deployment's own backup, and no root token left in a file or an environment variable by bootstrap. Total loss of the store is a rehearsed recovery path rather than an outage nobody has tried. **Status: NOT MODELLED.** |
| A restore resurrects a revoked credential or a deleted account | ⭐ Added 2026-09-04, extending the backup row above, which covers tampering with a backup and not the act of restoring one. Restore is itself a security event: authorized, audited and anchored like any other. FreeIPA, Postgres, Keycloak and the audit chain restore to a consistent point in a stated order, and every credential revoked between the snapshot and the restore is re-revoked as part of the procedure. The procedure is exercised on a cadence, because an untested restore is a claim. **Status: NOT MODELLED.** |
| Recordings and audit entries are read, kept or exported by people who should not | ⭐ Added 2026-09-04. This is the most sensitive data the product holds. Encryption at rest, a retention period with real deletion at the end of it, an audit entry for every view and every export, and a stated position on redaction. Reading a recording is itself a recorded act. **Status: PARTIAL**, and ⚠️ **corrected 2026-09-04: retention is partly built.** `recordings.list` and `recordings.read` are policy-gated, and a 90-day ISM retention policy is installed against the session indices at startup (`src/api-gateway/cmd/server/main.go:2552`) — but when it cannot be installed the gateway logs a warning and continues, so the deletion half is conditional on an admin indexer credential nobody checks. Export logging cannot exist because there is no `recordings.export` operation in `policies/api/authz.rego` at all. Encryption at rest and redaction are not built. See TMSR-03 and TMSR-04. |
| Stolen break-glass credentials | ⭐ Added 2026-09-24. The console break-glass account (the second account the installer seeds into `super-admins`, designated by its `ipaUniqueID` in `bootstrap.breakglass_ipa_unique_id`) enters admin mode with **no approver** — by design; that is its purpose — so its password and second factor together are a `super_admin`. Required controls: both are sealed offline and never used for daily work; activation needs fresh MFA and a live check that the account is still in `super-admins`, so removing it from the group switches activation off; every activation emits `iam.jit.grant_breakglass_activated`, which the one-minute severity-1 break-glass detection monitor watches, and pages every super-admin; any standing super-admin can revoke the grant without first elevating; the account can never approve an elevation; after every use its password and second factor are rotated and re-sealed. This is a different path from the host break-glass boundary above (hardware token, audited bastion, SSH over WireGuard), which is unchanged. **Status: BUILT** for activation, the membership check, the event, the monitor, the page and revoke (`src/api-gateway/internal/handlers/jit/breakglass.go`). ⚠️ Open: an attacker who is already elevated can reset, disable or remove the break-glass account, and so the recovery path, and nothing marks that write as touching the designated identity. |
| Operator pivots from API gateway host to FreeIPA host | Control plane components run on separate hosts (or at minimum, separate user namespaces with no shared sockets). The API gateway service account has no SSH access to other control plane hosts.   |

### Cross-cutting: what every other row in this section rests on

⭐ Added 2026-09-04, after an outside reader worked through the published corpus. Each of these sat
underneath rows above and was written down nowhere, and a control that is only implicit is not in the
contract. The requirement holds whatever the status says.

| Vector | Required control |
| ------ | ---------------- |
| A clock is rolled back, or NTP is answered by an attacker | Kerberos ticket validity, X.509 and SSH certificate lifetimes, JWT expiry, MFA freshness (`step_up_mfa_max_age`), enrollment-token expiry, bundle TTL and anchor liveness are every one of them clock-dependent, and a host that controls its own clock controls all of them locally. Time comes from an authenticated source, NTS or NTP restricted to the control plane. The gateway refuses an assertion whose issue time falls outside a bounded skew from its own. A host whose clock cannot be trusted fails the decision rather than being handed a stale `max_age` for free. **Status: NOT MODELLED.** Nothing in this document previously said where time comes from. ⭐ Made checkable 2026-09-26 (external review): "a host whose clock cannot be trusted" needs a test, or no observation can show the row unmet. A managed host is in the untrusted-clock state when its time source reports it unsynchronised, when its last authenticated sync is older than a stated bound, or when its clock differs from the gateway's, measured on every bundle pull, by more than a stated skew; the gateway applies the same skew bound to every assertion it accepts. In that state, local decisions that depend on an age, an expiry or a lifetime fail, the agent reports the state and the compliance surface shows it. The two bounds are owed as numbers on this row. The review proposed 60 seconds of skew and 10 minutes since the last authenticated sync; neither is ruled yet. |
| A disabled account, removed group, revoked certificate or withdrawn grant keeps working | One table, and it does not exist yet: for user disablement, group removal, Kerberos TGT, access JWT, refresh token, SSH user certificate, SSH host certificate, host X.509, SSSD cache, OPA bundle, VPN profile and RADIUS client, the maximum time each stays effective after revocation and the behaviour of each while its authority is unreachable. Nothing may be described as immediate unless a mechanism makes it so. Short lifetimes are a bound on damage, not a revocation path. **Status: NOT MODELLED.** Individual TTLs are configured in several places and no row states the sum of them. ⭐ Extended 2026-09-26 (external review): other rows send credentials to this table that its list omits. The table also carries the host keytab; enrolment tokens issued to or by a disabled account; JIT and break-glass grants; approvals already granted; agent certificates and authority derived from an agent's sponsor; AD-federated account state; Samba domain user and machine accounts; and recording and playback access. Each entry states its mechanism, its measured bound and its behaviour while its authority is unreachable. |
| An operator-configurable destination is pointed somewhere else and adamance authenticates to it | The `secret_ref` rule from the RADIUS module is the general rule and not a RADIUS one. Every outbound destination an operator can configure — anchor sinks (git, email, SSH or SCP, object store), webhooks, SMTP, package sources, the OIDC issuer, Wazuh, and AD or LDAP endpoints — resolves its credential from a name the code owns rather than a path or URL taken from a row, refuses link-local and cloud-metadata addresses, does not follow a redirect to another host, and re-validates at the moment of use because validating on write is only sound while writes are the only way rows appear. **Status: PARTIAL.** Held for AD (`adsecrets`) and RADIUS (`radiussecrets`), which is where it was discovered. Unstated everywhere else. See [`THREAT_MODEL_network_modules.md`](THREAT_MODEL_network_modules.md). |
| Two names that are equal in one layer and different in another | One canonical form for a principal, defined once: case folding, Unicode normalization, realm and FQDN handling, and the mapping between the Keycloak subject id, the FreeIPA DN, the Samba SID and the SSH principal. An account deleted and recreated under the same name is a different subject. Authorization keys on the stable identifier and never on the display name. **Status: NOT MODELLED**, and it is the failure mode that kills identity products: two strings that one layer calls equal and another does not. |
| Storage fills and the control plane stops deciding | Every store an unprivileged actor can grow — recordings, audit entries, Wazuh data, spool directories — has a quota and a stated behaviour at the limit, and that behaviour is refusal rather than silent loss. A session that cannot be recorded is already refused; an audit entry that cannot be written gets the same direction. **Status: PARTIAL.** |
| An unauthenticated or low-privilege caller exhausts the gateway | Connection and request caps, bounded request bodies, bounded OPA evaluation time, per-IP and per-principal limits on the expensive routes, and a bound on LDAP group sizes that a single decision will expand. The `/oauth/token` limiter is per IP and the Keycloak failure counter is per account, so a spray distributed across many source addresses and many accounts is under both. **Status: PARTIAL.** Denial of service is the least-covered category in this document and that was not a decision anyone made. |
| Losing a dependency changes the answer and nobody wrote down which way | For each of OPA, FreeIPA, Postgres, Keycloak and the anchor sink, this document states whether losing it fails open or closed. Undeclared is the same as unknown, and unknown at the moment of an outage is decided by whoever wrote the error path. **Status: NOT MODELLED.** |
| A module is switched off, or back on, while its old authority is still in force | ⭐ Added 2026-09-26 (external review). Each optional module (Samba, VPN, RADIUS, DNS, the SIEM, recording) defines an authorised enable and disable transition covering its listeners, processes, credentials, grants, sessions, queued work, generated host configuration and retained data. Enabling exposes nothing before the module's required controls are active. Disabling reports complete only when the end state is observed at the enforcement points, and an incomplete transition stays visible and retryable. Re-enabling never reuses a revoked credential or revives an obsolete grant, and no transition removes a control the rest of this contract still needs. **Status: NOT MEASURED.** |
| A secret is copied into logs, traces, errors or a support bundle | ⭐ Added 2026-09-26 (external review). Logs, traces, metrics, error bodies and support bundles are built from field allowlists and never carry passwords, bearer tokens, private keys, unseal material, refresh tokens or reusable enrolment secrets. A sensitive value keeps its classification across component boundaries and error wrapping. Diagnostic collection and support bundles always exclude secret files and process memory; forensic acquisition, where it is ever needed, is a separate, explicitly authorised process and never enters a diagnostic artefact. Access to, retention of and export of diagnostic artefacts is governed. A secret that does leak into one is treated as compromised and contained, not only deleted from the log. **Status: NOT MEASURED.** |


### Cryptographic baseline

These are non-negotiable defaults; deviation requires explicit documentation:

- TLS: 1.3 only. No 1.2 fallback. Cipher suites limited to AEAD (AES-GCM, ChaCha20-Poly1305).
- Key exchange on agent-to-server mTLS: hybrid post-quantum, X25519 with ML-KEM-768, pinned in
  `src/common/mtls/tlsconfig.go:21-23` and asserted in `src/common/mtls/tlsconfig_test.go:81-83`.
  ⭐ Added 2026-09-02: this baseline had no post-quantum line while the property was already built and
  is the transport claim the public site leads with. Hybrid is the point. If the post-quantum half is
  broken the classical exchange still stands, and if the classical half falls to a quantum computer the
  other one holds. The threat is recording now and decrypting later, which needs patience rather than a
  quantum computer today.
- ⚠️ Signatures are **not** post-quantum. Certificates and identities are Ed25519, which is classical.
  Moving those is a later transition and nothing here should be read as claiming it. Traffic recorded
  today is still protected, because breaking a recording means breaking the exchange.
  ⚠️ **Status added 2026-09-26 (external review), measured at `27679898d`.** "Certificates and identities are Ed25519" is the requirement and is not yet true of host and agent certificates: enrolment and every renewal generate an RSA-2048 key (`src/client-agent/internal/enroll/enroll.go:231`, `src/client-agent/internal/certrenew/certrenew.go:262`). Status for that clause: **PARTIAL**. A component that genuinely cannot take Ed25519 gets a recorded exemption, as the SMTP TLS 1.2 floor does.
- Kerberos: AES-256 only. RC4 and single-DES disabled in `kdc.conf`.
- JWT: EdDSA (Ed25519) only. HMAC algorithms (`HS256` etc.) disabled at validation time.
- Password hashing inside any adamance-owned component: Argon2id with parameters reviewed annually.
- Long-lived signing keys (Dogtag CA, SSH CA / step-ca (K-05), JWT, OPA bundle) live in HSM-backed storage where
  available; for homelab deployments, sealed offline files with documented rotation. The X.509 (Dogtag) and SSH
  (step-ca) CA chains are kept separate per CRYPTO-07.

## Explicit non-goals

State these so we don't accidentally drift into pretending we cover them:

- We do not defend against a **nation-state actor with physical access** to a control plane host.
- We do not defend against a **compromised CPU or firmware-level supply chain** attack.
- We do not defend against an attacker with **simultaneous compromise of two operator accounts** that include the
  second-approver role.
  ⭐ Extended 2026-09-26 (external review): for policy changes that need two approvers the threshold is three accounts, not two. By design, the console break-glass account is outside this non-goal's protection: its sealed password and second factor are one credential pair with no approver, and its controls are custody, the live membership check, the page and rotation after use (see "Stolen break-glass credentials").
- We do not provide **anti-coercion** (rubber-hose attacks).

## Open decisions: recorded at the end of this document

The authoritative table is **[Open decisions](#open-decisions)**, in the second-pass review below.

A duplicate copy of it stood here until 2026-08-03, carrying TM-01 through TM-05 with byte-identical
text. The later table is a strict superset (TM-01 through TM-25) and records which decisions have since
been RESOLVED, so the copy here could only ever go stale against it; two tables of the same IDs is how
a document drifts from itself. It was removed rather than reworded; nothing was lost, because every row
it held is still in the authoritative table verbatim.

## Revision history

| Date       | Change        | Author |
| ---------- | ------------- | ------ |
| 2026-05-24 | Initial draft | - |
| 2026-05-26 | Second pass against as-built system (M5 complete). ⚠️ Corrected 2026-09-02: this row read "Verified all required controls are implemented", which the same pass disproves on its own pages. It found violations, stubs and missing implementations, and later passes found more. The claim is left quoted rather than deleted, because a false assurance in a revision history is exactly the kind of thing later readers trust without re-checking. Added TM-06 through TM-10. |,      |
| 2026-07-11 | V1 verification pass; re-verified every contested TM item against live source (see the ⭐ section at top). Fixed 2 real residuals (client-agent join TLS 1.2→1.3; Keycloak brute-force protection). Reconciled the stale 2026-05-26 narrative vs. the resolution table. Fixed malformed markdown in the Revision-history + Open-decisions tables. Descoped TM-25 (multi-tenancy removed for V1). | project maintainer |
| 2026-08-31 | Bundle-scoping row refuted. It had read "✅ CONFIRMED / Finding: NONE" and nothing implemented the control. Corrected in place with the false text quoted. | - |
| 2026-09-01 | Correction pass over MFA, step-up mechanism, FIM (TM-12) and the crypto-config passage. Several rows had named files and middleware that have never existed in this repository. | - |
| 2026-09-02 | Reconciliation pass. Removed the internal precedence rule that told readers which half of this document to believe. Corrected the LDAP/Kerberos exposure row against the shipped HA compose, the dual-control approver count (one approver by default, not two), and the audit-log row that credited unwired Wazuh FIM. Added the post-quantum key-exchange baseline, which was built and undocumented. Fixed a false assurance in the 2026-05-26 revision-history row. Seven subsystem threat models split out and linked from the header. | project maintainer |
| 2026-09-04 | Correction pass, prompted by an external read of the published corpus. Six rows that had gone stale are corrected in place and each quotes its former text: the account-lockout row, the TM-08 digest-pinning paragraph, the TM-10 enrollment hard stop, the TM-16 critical-bundle gap, the TM-19 paragraph that named a nonexistent `authz.RequireMFA()` middleware, and the TLS 1.2 internal-client violation. The reading rule at the top now states that this document is a contract rather than a status report, and that a threat stays until it stops being technically possible. Added: a cross-cutting section covering trusted time, revocation convergence, credentialed egress, identity canonicalization and availability; approval binding and audit atomicity; the OIDC, rendering and object-authorization surface of the console; enrollment CA bootstrap, token entropy, host cloning and decommission; OpenBao, restore and recording privacy; and the SSH KRL question. Three assets and two trust boundaries added. | project maintainer |
| 2026-09-05 | Synchronization pass, prompted by a second external read and by four independent model reviews. The finding was not a missing threat: this corpus held the new conclusion and several active summaries of the superseded one at the same time, because corrections were filed on the row that was wrong and not propagated to the rows repeating it. Corrected in place, each quoting its former text: TM-30 (re-sequenced, and a note that it is a requirement rather than a claim), TM-31 and the lateral-movement row (the withdrawn "does not witness A4" absolutism, ⚖️ OPERATOR REFUTED), TM-32 (the ruling had already been made), TM-36 ("in no threat model" was false of this file), TM-41 (it cited an A4 definition this document does not give, and overstated what the port exposure proves), TM-42 (its proposed evidence was all producer-generated), the asset table (the audit chain HMAC key was missing entirely and a cross-reference dangled onto it; ranks renumbered), the header date, and the row that called the anchor a signed copy leaving the box. Added: A4 split into five capability profiles, with a rule that subsystem models reference them rather than restate them. | project maintainer |
| 2026-09-15 | One row only. The LDAP/Kerberos exposure row's 2026-09-02 correction was WITHDRAWN and the required control restored unhedged: The HA overlay was rewritten on 2026-09-05 and the contradiction it recorded no longer exists. Re-measured against the tree — the HA overlay's only publication binds `${ADAMANCE_HA_LB_BIND:-127.0.0.1}` and both replicas carry `ports: !reset []`; the composed project publishes nothing on all interfaces. ⛔ **This was NOT a whole-document pass and `Last reviewed` was deliberately not advanced.** ⛔ TM-41 still carries the same stale clause (four port maps that are absent from `deploy/docker-compose.ha.yml`) and was left alone. | - |
| 2026-09-24 | Two rows only. Added the console break-glass account as a trust boundary and the "stolen break-glass credentials" vector, by design: the account enters admin mode with no approver, pages every super-admin, and cannot approve. The host break-glass boundary row is unchanged — it is a different path. ⛔ Not a whole-document pass; `Last reviewed` was not advanced. | - |
| 2026-09-26 | External review pass. Three reviewers read the whole corpus; every finding that survived checking is in place and dated 2026-09-26, and every corrected sentence quotes what it replaced. New rows: first-install authority, token acceptance context, certificate purpose, refresh-token families, non-browser injection, SSH destination authentication, policy-lease age, local decision inputs, coherent policy activation, module enable and disable, secrets in diagnostics, and the A4b adversary. Corrected: TM-09, TM-13, TM-16, TM-18, TM-20, TM-32, TM-41, TM-42, TMS-05, TMS-06, TMS-11, TMS-22, a CA-bootstrap clause no server could enforce, two "where possible" hedges, three asset rows, and two NOT MODELLED statuses that TM-34 and TM-40 had already measured. Every status change was re-measured at `27679898d` before it landed, and one reviewer finding was refuted by that measurement: an agent does not clear step-up when the MFA opt-out is taken. ⛔ Not a whole-document re-measure; `Last reviewed` was not advanced. ⚠️ Corrected 2026-09-27: this copy already defined A4b, in the capability-profile table under A4 (added 2026-09-05), so the separate A4b section this pass added duplicated it, sat above that table, and was removed. Nine notes this pass appended to two-column rows had also landed in the Vector cell instead of the Required control cell; they were moved without changing a word. | project maintainer |
| 2026-09-27 | The maintained copy took this copy's own 2026-09-04 and 2026-09-05 corrections, and this copy took the measured 2026-09-04 versions of four rows it had missed: the browser-facing OIDC flow, console rendering, SSH certificate revocation and approval binding. The 2026-09-26 header line moved below the 2026-09-05 correction it had split. | project maintainer |
| 2026-09-27 | One row only. Added TM-43, operator-refuted: any authenticated user may ask for a JIT super_admin grant; only a standing super-admin may approve one. The maintainer's reasoning for the ruling was added to the row the same day. | - |

---

## Second-pass review: as-built vs. as-documented (2026-05-26)

This section walks every threat-control pair from the initial threat model and evaluates each against the
actual as-built system (post-Phase 5). It surfaces gaps, over-matches, and new gaps not captured in the
original.

### Verification method

- Read the design doc.
- Read the actual implementation (Go source under `src/`, compose files, configs).
- Asked: does the code actually implement the described control?

---

### Initial access (A1)

#### TMS-01 · BUILT · Exposed admin UI / API on the public internet
**Required control:** V1 is private/VPN-only; bind to private network / VPN; no public internet exposure.

**As-built:** ✅ CONFIRMED.

**Re-measured 2026-09-22 at `ef276bcf`:** BUILT. The shipped single-host stack publishes exactly two host ports and both are loopback by default: deploy/setup/docker-compose.setup.yml:463 binds ${ADAMANCE_MTLS_BIND:-127.0.0.1}:8443 and :651 binds a literal 127.0.0.1 edge, the FreeIPA overlay declares no ports: at all, and the in-box override does ports: !reset []. The HA overlay's only publication is ${ADAMANCE_HA_LB_BIND:-127.0.0.1}:8463 with both gateway replicas carrying ports: !reset []. The gateway's own :8080 / :8443 in configs/api-gateway/api-gateway.prod.yml:25-26 are container-internal and reach the host only through those loopback publications, so the row's no-ListenPublic claim still holds. Two live caveats the row does not carry: ADAMANCE_MTLS_BIND lets an operator bind all interfaces and nothing refuses that, and the edge has no bind variable at all, which is why the console and the enrolment one-liner are unreachable from another machine. Has it ever run: n/a - always-on compose configuration, not a pipeline or a drill. Caveat, and it is the row's real weakness: nothing has rendered the composed project with docker compose config at runtime (tracked as an open gap), and the production-shaped setup stack has never been installed, so this is measured off the files and not off a running host. Evidence: `deploy/setup/docker-compose.setup.yml:463` · `deploy/setup/docker-compose.setup.yml:651` · `deploy/setup/compose.d/20-freeipa.yml:31` · `deploy/docker-compose.ha.yml:376` · `deploy/docker-compose.ha.yml:123`
`src/api-gateway/cmd/server/main.go` binds two listeners:
- `ListenHTTP` (plaintext, unauthenticated), intended for health/readiness probes only.
- `ListenMTLS` (TLS, service-to-service), for managed hosts and service mesh.

There is no `ListenPublic` or equivalent. The admin UI is served by a separate `admin-ui` service behind
the reverse proxy. No component binds to `0.0.0.0` with a port documented as publicly reachable.
The `Caddyfile` (per `scripts/dev-up.sh` and M1 artifacts) is the internet-facing boundary.

**Finding:** NONE. Control is implemented as described.

---

#### TMS-02 Credential stuffing against admin UI
**Required controls:** MFA required for all admin accounts; rate limit on `/oauth/token`; account lockout
after N failed attempts with exponential backoff.

**As-built:** ⚠️ PARTIAL.

- MFA requirement: ⚠️ **PARTIAL, corrected 2026-09-01. This bullet read "✅ CONFIRMED" and named three
  things that are not true.** `src/api-gateway/internal/middleware/mfa.go` has never existed in this repo
  (no commit in `git log --all --diff-filter=A` adds it); there is no `mfa_verified` JWT claim anywhere in
  the tree; the `mfa_verified_at` columns in `src/api-gateway/internal/storage/refreshtokens/store.go`
  and `src/api-gateway/internal/storage/approval/store.go` are unrelated refresh-token and approval-proof
  timestamps; and the OTP authority is Keycloak, not FreeIPA;
  `src/api-gateway/internal/handlers/users/handler.go:1561-1562` records that the FreeIPA `otptoken` path
  is cosmetic because Keycloak never checks it. No WebAuthn authenticator is implemented here either: no
  Go code enrols or verifies a WebAuthn credential. `webauthn` appears only as an accepted `amr` value
  (`configs/api-gateway/api-gateway.prod.yml:81`, `configs/api-gateway/api-gateway.dev.yml:93`), as one of
  the pass-through approval-proof method strings (`src/api-gateway/internal/storage/approval/store.go:113`,
  labelled by `web/admin-ui/src/lib/approverproofs.ts:96`), and in an unbuilt draft design.

  ⚖️ Updated 2026-09-24: Keycloak now enrols and verifies a security key. The realm's
  `stepup-2fa` accepts `webauthn-authenticator`, the gateway starts the enrolment
  (`kc_action=webauthn-register`, in `src/api-gateway/internal/handlers/auth/keycloak.go`), and an
  MFA reset deletes keys (`src/api-gateway/internal/keycloakadmin/client.go`). So `webauthn` no
  longer appears only in the places listed above. Go code still neither enrols nor verifies a
  credential itself, and the gateway sees a key step-up only as `acr=gold`.
  ⚖️ Updated 2026-09-24: an administrator's MFA reset now also stops an enrolment already
  open in a browser. Keycloak loads a provider JAR of ours (`src/keycloak-factor-guard/`, committed
  with a sha256 pin at `deploy/setup/keycloak/providers/adamance-kc-factor-guard.jar` and mounted
  read-only by every compose file that runs Keycloak) that replaces `webauthn-register`,
  `webauthn-register-passwordless` and `CONFIGURE_TOTP` by provider id. Each records the user's
  second-factor set at the step-up and refuses the credential write — `error=access_denied`, no
  `code` — when that set changed, when the user's Keycloak `notBefore` is at or after the step-up,
  or when a user who already holds a step-up factor (an OTP or a security key) enrols from a sign-in
  that did not prove one (LoA below 2). It also records the step-up second as the login's
  `auth_time`. `make drill-kc-factor-guard` (ci-full) proves each refusal on the pinned Keycloak,
  and proves the same legs reproduce the defect without the JAR; install, `./adamance restart`
  and `verify_upgrade` read the guard back from serverinfo. What it does not close: a Cancel, or a pause on an action it does not wrap,
  still ends in a code, whose session is the gateway's to refuse on `auth_time` against
  `notBefore`; a password-only sign-in by a user who holds no factor can still enrol one;
  a submission that lands while the reset itself runs (after it lists the credentials to delete,
  before the deletes) keeps its new credential; Admin REST credential writes run no ceremony; and
  the named admin and break-glass log in with a Keycloak-local password no gateway operation
  rotates, so an MFA reset does not contain them.
  What is true: the JWT carries `mfa_enabled` and `mfa_age`, minted at
  `src/api-gateway/internal/session/session.go:438-439` and read back at `:676-687`, where a missing or
  unparseable `mfa_age` fails CLOSED to the one-year `NeverVerifiedMFAAgeSeconds` sentinel, not 0.
  ⚠️ **Enforcement is per-operation, not per-account.** Nothing requires an admin to hold a second factor
  in order to log in: `src/api-gateway/internal/handlers/auth/keycloak.go:948` (`mfaFromIDToken`) counts a
  login as MFA-verified only when the id_token's `acr` is allow-listed in `freeipa.oidc_mfa_acr_values` or
  its `amr` intersects `oidc_mfa_amr_values`; anything else yields `NeverVerifiedMFA()` **and the login
  still succeeds**; `src/api-gateway/internal/handlers/auth/keycloak.go:620-633` mints the session with whatever state that returned. Such a
  session is then refused every step-up-gated operation (see the step-up row below) unless the
  deployment-wide opt-out has been taken:
  `src/api-gateway/internal/db/migrations/0093_super_admin_mfa_policy.sql` seeds the `mfa_policy`
  singleton whose `second_factor_required` (default TRUE) can disable the gate entirely.
  `src/api-gateway/internal/config/config.go:868-871` refuses boot if a password-only (LoA1) `acr` alias
  is allow-listed as MFA.
- Rate limiting on `/oauth/token`: ✅ RESOLVED. `src/api-gateway/internal/middleware/ratelimit.go` adds `OAuthTokenRateLimiter` (5 req/min per IP+User-Agent, keyed by SHA256(IP+UA)). `OAuthTokenRateLimitMiddleware` is wired into the router in `main.go`. Rate-limit events are emitted as structured audit events. See **TM-06** HANDOFF.
- Account lockout after N failed attempts: ✅ RESOLVED (2026-07-11). ⚠️ **Corrected 2026-09-04: this
  row read "❓ NOT FOUND. No lockout logic in `src/api-gateway/`. FreeIPA may apply its own (not verified
  in code). This is a gap for the API gateway layer." and it stayed that way for 55 days after the gap
  was closed.** The lockout is not in the gateway and was never going to be: it belongs to the identity
  provider. `deploy/setup/keycloak/realm-adamance.json.tmpl` sets `bruteForceProtected:true`,
  `failureFactor:10`, `permanentLockout:false`, `maxFailureWaitSeconds:900`. Dev provisions its realm
  separately and additionally carries the OIDC 5/min per-IP limit. What is still not written down is the
  interaction between the two and whether a distributed spray under the per-IP threshold reaches the
  failure counter at all, which is the availability row in the cross-cutting section.

---

#### TMS-03 Phishing of admin session cookie
**Required controls:** Short JWT lifetime (≤15m); refresh tokens bound to IP and User-Agent; MFA step-up
required for sensitive operations.

**As-built:** ⚠️ PARTIAL.

- JWT lifetime ≤ 15m: ✅ CONFIRMED. `src/api-gateway/internal/config/config.go` defaults `TTLMinutes: 15`.
  Line 137: `if c.JWT.TTLMinutes == 0 { c.JWT.TTLMinutes = 15 }`.
- Refresh token bound to IP and User-Agent: ✅ RESOLVED. `src/api-gateway/internal/session/session.go` adds `RefreshTokenStore` with IP+UA binding enforcement. `Validate()` rejects on IP mismatch or UA mismatch. Single-use (consumed after validation). Security events emitted on mismatch (`auth.refresh.fail` with IP and UA). Wired into `auth.TokenHandler` in `src/api-gateway/internal/handlers/auth/token.go`. HTTP-layer integration tests in `src/api-gateway/internal/handlers/auth/token_integration_test.go`. See **TM-07** HANDOFF.
- MFA step-up for sensitive operations: ✅ CONFIRMED, **mechanism corrected 2026-09-01: there is no
  `authz.RequireMFA()` middleware.** The only `RequireMFA` declared in the tree is
  `src/api-gateway/internal/handlers/users/handler.go:1624`, an admin action that forces a user to enrol
  OTP (routed at `src/api-gateway/cmd/server/main.go:4553`), a different thing entirely. Step-up is
  enforced by the policy, not by a per-route Go middleware: `policies/api/authz.rego`'s
  `check_user_with_mfa_stepup` family gates 79 distinct operations, including
  `machine.create_enrollment_token`, `policy.publish`, `user.update` and `ssh_cert.sign`. A factor older
  than `step_up_mfa_max_age` (default 300s, `policies/api/authz.rego:3408`) returns the obligation
  `require_mfa_age_max_seconds` (`policies/api/authz.rego:2582`), which
  `src/api-gateway/internal/authz/decision.go:268-285` maps to `MFAStepUpRequired`;
  `src/api-gateway/internal/authz/middleware.go:519-520` then calls `writeStepUp` (`:981`), answering 401
  `MFA_STEP_UP_REQUIRED` with a `challenge_url`. The middleware is mounted across the authenticated API at
  `src/api-gateway/cmd/server/main.go:3716` (`rapi.Use(authzMw.Handler)`). ⚠️ Every clause of the gate is
  conditional on `second_factor_required` (`policies/api/authz.rego:3461`, default true); the
  deployment-wide opt-out an operator can write to the `mfa_policy` table. The literal `mfa_step_up`
  obligation string comes from `governance.require_approval`
  (`policies/governance/require_approval.rego:154`), not from `adamance.api.authz`.

---

#### TMS-04 Vulnerable upstream container image
**Required controls:** Pin all images by digest; weekly Trivy scan in CI with blocking severity threshold;
documented monthly patch cadence.

**As-built:** ✅ VERIFIED IN CODE.

- Digest pinning: `deploy/dev/docker-compose.dev.yml` uses digest-pinned images for all external
  services (`postgres@sha256:...`, `smallstep/step-ca@sha256:...`, `caddy@sha256:...`).
  `digest-check` CI job (release.yml) enforces that no non-digest image tag passes CI for both
  `deploy/dev/docker-compose.dev.yml` and `package/adamance/docker-compose.yml` (single-host production).
  Local `adamance/*:dev` images, `${VAR}` overrides, and `build:` blocks are correctly excluded.
  ⚠️ **Corrected 2026-09-04: this paragraph read "The single-host package
  (`package/adamance/docker-compose.yml`) still contains non-digest images
  (`freeipa/freeipa-server:rocky-9-4`, `openpolicyagent/opa:latest`, `wazuh/*:4.8.0`) that must be
  resolved and pinned before production use", and the Finding line directly below it already said the
  opposite.** All five images in `package/adamance/docker-compose.yml` are `@sha256:`-pinned as of
  2026-07-11. A digest pin is not provenance: it says the bytes did not change, not that the bytes came
  from the build anyone believes they came from. Signed provenance for the images and for the release
  artifacts is a separate requirement and is not met.
- Trivy scan in CI: `release.yml` includes Trivy scanning of container images with blocking
  severity threshold (HIGH/CRITICAL).
- Monthly patch cadence: documented in the release process and the design docs.

**Finding:** TM-08 (RESOLVED); `deploy/dev/docker-compose.dev.yml` uses sha256-pinned images. Single-host package (`package/adamance/docker-compose.yml`) fully resolved: all 5 images are now digest-pinned with `@sha256:`.

---

#### TMS-05 Direct exposure of LDAP/Kerberos ports
**Required controls:** Only the reverse proxy is in the edge zone. LDAPS/Kerberos are not reachable from
outside the control plane subnet.

**As-built:** ⚠️ NOT VERIFIED.

The Docker Compose network configuration was not reviewed in this pass. `docker-compose.yml` was not present
in the root, and no single unified compose file has ever existed; not in the root, not at the top of `deploy/`.
The installed single-host stack is `deploy/setup/docker-compose.setup.yml`, the `deploy/setup/compose.d/*.yml`
overlays, and conditionally `deploy/setup/docker-compose.inbox.yml` (when the `.inbox` marker exists) and
`deploy/setup/docker-compose.tpm.yml` (when the host has a TPM), assembled by `compose_file_args` in
`deploy/setup/lib/compose.sh`. The control plane network segmentation is documented in the
architecture design but not verified against a running compose file. Verify it against
that stack, whose base file declares one `internal` bridge and publishes exactly two host ports, both
loopback-bound by default (api-gateway host-mTLS `${ADAMANCE_MTLS_BIND:-127.0.0.1}:8443`, edge
`127.0.0.1:8453`), whose FreeIPA overlay `deploy/setup/compose.d/20-freeipa.yml` declares no `ports:` at all,
and whose conditional overrides add none (the in-box override does `ports: !reset []`), and against
`deploy/docker-compose.ha.yml`, whose `ipa-replica` publishes seven host ports on all interfaces
(`81:80`, `444:443`, `390:389`, `637:636`, `89:88/udp`, `465:464/udp`, `124:123/udp`), before first deployment.

⚠️ **Corrected 2026-09-26 (external review), measured at `27679898d`.** The sentence above describes the HA overlay before 2026-09-05. Today `deploy/docker-compose.ha.yml` publishes only `${ADAMANCE_HA_LB_BIND:-127.0.0.1}:8463` (`:376`), and both replicas carry `ports: !reset []` (`:123`, `:144`).

⚠ Corrected 2026-09-01: this passage sent the reader to `deploy/docker-compose.yml`, which git has never
contained. The top of `deploy/` has only ever held per-concern compose files; today `docker-compose.ha.yml`
(renamed from `docker-compose.t2.yml`), `docker-compose.keycloak.yml` and `docker-compose.siem.yml`, with the
rest under `deploy/dev/`, `deploy/observability/` and `deploy/setup/`.

---

### Enrollment (A1, A2)

#### TMS-06 Unauthorized host joining the domain
**Required control:** Enrollment requires a one-time scoped token, bound to hostname, expiring within 24h.

**As-built:** ✅ CONFIRMED.

`src/api-gateway/internal/enrollment/handler.go`:
- `CreateToken` generates a UUID-based token with operator binding (`actor`) and `TTLHours` (default 24,
  max 168 / 7 days).
- Token is single-use: `store.CreateToken` marks it consumed atomically.
- CSR hostname matching: the `enroll` handler in `src/client-agent/internal/enroll/enroll.go` generates a
  CSR with `CN=$(hostname)` and the API gateway enrollment handler must verify the CSR's CN against the
  token's bound hostname. The enrollment store's `ConsumeToken` method handles this.
- All failures (hostname mismatch, expired, replay) emit Wazuh alerts via `auditFn`.

**Finding:** NONE. Control fully implemented.

⚠️ **Corrected 2026-09-26 (external review), measured at `27679898d`.** The finding above says the control is fully implemented, and the as-built line reads "✅ CONFIRMED". The required control is a token "expiring within 24 hours"; the handler accepts a lifetime of up to 168 hours (`src/api-gateway/internal/enrollment/handler.go:397`, "token lifetime must be between 1 and 168 hours"). Twenty-four hours is the default, not the ceiling, so this control is **PARTIAL**.

---

#### TMS-07 · PARTIAL · MITM of the install script
**Required control:** Install artifact served over TLS only, from a pinned hostname, SHA-256 published.

**As-built:** ✅ CONFIRMED.

**Re-measured 2026-09-22 at `ef276bcf`:** PARTIAL. 🚨 The 2026-05-26 verdict was OVERSTATED. Every one of the four bullets holding this ✅ CONFIRMED is now false or has never executed, and the row answers the wrong artifact. The script does NOT fetch from GitHub Releases: agent_install.sh:9-10 and :160 fetch the binary from the GATEWAY via an operator-supplied SERVER, and the integrity check at :127-144 compares sha256 against either an operator-supplied EXPECTED_SHA256 or the gateway's own X-Content-SHA256 header, which that same gateway minted at agent_install.go:280 from its own res.Hash - circular, and a 2026-09-18 measurement records that no route serves the detached signature at all, the only signature-shaped line in the script a host runs being a comment at :117. The cosign claim is code that has never run: release.yml:329-331 does keyless sign-blob plus verify-blob pinned to repo / workflow / ref, but Actions is disabled repo-wide and there are 0 published releases, and every release built locally used the test key in the repository. Of the control's three conjuncts only TLS-only holds, and the artifact does not enforce even that - there is no scheme guard on SERVER and the fetch uses curl -L, so a redirect to http is followed; the pinned hostname does not exist for this script (the leaf-fingerprint pin at join_install.go:179 is the OTHER installer), and no SHA-256 is published anywhere, which is what TMI-02 and TMI-07 say is still owed. Has it ever run: NEVER for the mechanism the ✅ rests on. GitHub Actions is disabled at the repository level (gh api actions/permissions returns enabled false) and there are 0 published releases, both measured 2026-09-21 and recorded in THREAT_MODEL_installer.md, so no artifact has ever carried a cosign signature and no release page has ever published a checksum. The host-side sha256 check in agent_install.sh:127 IS an always-on code path and does fail closed at :138 and :141, which is why this is PARTIAL rather than NOT_BUILT - NOT_BUILT is arguable, since for the script itself only the TLS conjunct holds. NOT checked: the gh api calls were not re-run (2026-09-21 data) and the curl -L redirect behaviour was not tested, only the flags were read. Evidence: `src/api-gateway/internal/handlers/installers/agent_install.sh:127` · `src/api-gateway/internal/handlers/installers/agent_install.sh:160` · `src/api-gateway/internal/handlers/installers/agent_install.sh:169` · `src/api-gateway/internal/handlers/installers/agent_install.go:280` · `.github/workflows/release.yml:329`
`src/api-gateway/internal/handlers/installers/agent_install.go`:
- `AgentInstallHandler` serves the script over HTTPS (via the TLS-terminating reverse proxy).
- The installer script (`agent_install.sh`) downloads the agent binary from GitHub Releases over HTTPS.
- The binary is served from `https://github.com/kevwillow/adamance/releases/download/v{version}/...`.
- The release.yml signs binaries with cosign; SHA-256 checksums are available from the release page.

**Finding:** TM-09 (NOTE). The installer script currently downloads the binary from GitHub Releases at
runtime. For air-gapped deployments this is not viable. The design doc acknowledges this ("Production deployments
distribute via an internal package repository, not `curl | bash`") but the V1 release artifact doesn't
include an internal-repo distribution path. This is documented as a gap but acceptable for V1 scope.

---

#### TMS-08 Replay of an enrollment token
**Required control:** Tokens are single-use and consumed atomically. Logged with source IP and resulting
host principal.

**As-built:** ✅ CONFIRMED.

`src/api-gateway/internal/enrollment/handler.go` + `src/api-gateway/internal/enrollment/store.go`:
- `ConsumeToken` is called once during the enrollment POST. The store marks the token as used atomically.
- Replay attempts return `errors.CodeTokenAlreadyUsed` and do not issue credentials.
- Audit event emitted with `event_type: iam.machine.token_created` and `event_type: iam.machine.enrolled`
  (on success).

**Finding:** NONE.

---

#### TMS-09 Hostname spoofing during enrollment
**Required control:** CSR CN must match the hostname bound to the token. CA refuses to sign for a name
not in the token.

**As-built:** ✅ CONFIRMED.

Enrollment handler (`src/client-agent/internal/enroll/enroll.go` and `src/api-gateway/internal/enrollment/handler.go`):
- The token is created with a bound hostname.
- The enrollment request includes a CSR.
- The API gateway validates that the CSR's CN matches the token's bound hostname before issuing a cert.
- Mismatch → enrollment rejected, alert raised.

**Finding:** NONE.

---

### Lateral movement (A2)

#### TMS-10 Compromised host uses its keytab to authenticate as another host
**Required control:** Host keytabs grant only the host's own identity. No transitive trust. User SSH uses
ephemeral certificates from the internal SSH CA.

**As-built:** ✅ CONFIRMED (design); NOT VERIFIED IN AGENT CODE.

The design is correct: host keytabs are single-host. The `lac` client CLI uses OIDC + SSH CA for user
access. However, `src/client-agent/internal/enroll/enroll.go` was not reviewed for the specific question of
whether the host keytab is scoped to the single host CN. This should be verified in the enrollment flow's
IPA API call (`ipa host-add` or `ipa service-add` scope).

**Finding:** TM-10 (LOW). Confirm host keytab scope in the FreeIPA IPA API call during enrollment.

**Resolution:** ✅ RESOLVED (2026-07-11). Superseded the 2026-05-27 assessment below.

⚠️ **Corrected 2026-09-04. The paragraph this replaced was left standing as if current and said:**
"⚠️ DEFERRED. HARD STOP: MISSING IMPLEMENTATION (2026-05-27, red-team). The enrollment handler does NOT
call FreeIPA at all. It is a stub that validates a token, writes to the Postgres `machines` table, and
returns `{status, hostname, host_group}`. No `ipa host_add`, no keytab generation, no host certificate
issuance." That was true when written and false by 2026-07-11: `enrollment/handler.go` calls `HostAdd`,
`GetKeytab` and `IssueHostCert` (:514/533/547), and the join-redeem path does the same. The original
finding — that the keytab is scoped to the single host CN — is answered by `HostAdd` issuing per-host,
and the residue is that nothing asserts it, so it is carried as a requirement rather than a claim.

---

#### TMS-11 Theft or misuse of the SSH CA signing key
**Required control:** SSH CA is a separate trust chain from Dogtag (CRYPTO-07); signing key in Vault Transit
or sealed offline file; short-lived certs; KRL distribution for revocation (⚠️ corrected 2026-09-26: this read "CRL distribution for revocation"; `sshd` consumes a KRL).

**As-built:** ⚠️ DESIGN CONFIRMED, IMPLEMENTATION NOT VERIFIED.

The SSH CA design is sound. `src/api-gateway/internal/handlers/sshca/crl.go` serves the CRL endpoint.
The `lac` CLI has `lac ssh-cert request` subcommand. However:
- The actual SSH CA signing key material (step-ca or equivalent) was not found in the `src/` tree.
  The SSH CA is described as living inside the API gateway or as a sibling service; the implementation
  path (`src/api-gateway/internal/sshca/`) exists as a handler package but the signing key management
  (where the private key lives and how it's used) was not verified.
- The OPA bundle signing key: `src/api-gateway/internal/bundle/bundle.go` handles bundle serving and
  signing verification, but the signing key location is not confirmed.

**Finding:** TM-11 (MEDIUM). The SSH CA implementation (signing key storage, key ceremony,
 Vault/HSM integration) needs a dedicated security review before V1 ships. The runbook
 An SSH CA rotation runbook exists but the actual key storage path was not verified in this pass.

**Resolution:** ✅ RESOLVED. No implementation gap; documentation clarified (2026-05-27, red-team).

The runbook was reviewed against the as-built system and K-05 specification. The key ceremony checklist (lines 346–396) covers all seven phases with two-person integrity. The as-built procedure matches the documentation. K-05 storage is file-based on an offline signer (`/opt/adamance-signer/`), consistent with the dev tier and the M3.5 as-built. Production HSM/Vault Transit is a V1.5 aspiration.

---

#### TMS-12 · PARTIAL · Compromised host modifies its own audit logs to hide activity
**Required control:** ⚠️ **Restated 2026-09-02.** This read "Wazuh agent forwards logs in real time.
Local log tampering is detected by FIM and raises a high-severity alert", and FIM is not wired anywhere
(TM-12). The control is that the record of a privileged action does not live on the host it describes:
it is written to the hash-chained audit store on the control plane, and a signed anchor of the head
leaves the box. A host tampering with its own local logs does not reach either.

**As-built:** ⚠️ PARTIAL, and weaker than this document previously claimed. adamance does **not**
install the Wazuh agent on managed hosts; the agent binary is operator-provided. A host without one is
still fully governed (nothing gates on `wazuh_agent_status`) but forwards **no** logs to the SIEM, so
this control is absent on any such host rather than merely unverified.

**Re-measured 2026-09-22 at `ef276bcf`:** PARTIAL. ⚠️ The 2026-05-26 verdict was UNDERSTATED — the tree does more than the row admitted. The verdict label is right and its supporting facts are now stale in the product's favour. src/client-agent/internal/wazuh/install.go is NOT deleted - it is back, fetching a gateway-served pinned package over the host's own mTLS with no apt or yum repository, and the join installer calls install_wazuh_agent at join_install.sh.tmpl:553 behind ADAMANCE_INSTALL_WAZUH_AGENT=1, so 'adamance does not install the Wazuh agent' is no longer true. The Go-side wazuh.Install has ZERO call sites outside tests, so the post-enrolment path repeats the unreachable-code trap of the file it replaced. Off-host capture of privileged actions is also more built than the row admits: the agent writes a sudoers drop-in logging every accepted command to a root-only file and pam.go calls it, with a packaged systemd unit draining it to the gateway. What still fails the control: that install fires only at the enrolment moment and the fleet opt-in is seeded false (verified in both the migration and installer step 62), recorded documents land in a separate signed store rather than the hash chain, a default install has no off-box anchor sink, and the anchor is signed with a key on the audited box. FIM is still unconfigured - the dev manager config's own header comment says syscheck / FIM is left to image defaults and the file carries no syscheck block naming any adamance path - so TM-12 is unresolved. Has it ever run: Sudo command capture and the drain have run in the dev prod-host container (deploy/dev/prod-host/entrypoint.sh:126). On a shipped install neither runs by default, because the host-governance opt-in is seeded false and the auth-stack install has one trigger only, enrolment. wazuh.Install has never run - no caller exists. No FIM rule covering /var/log/adamance has ever existed, so nothing to have run there. Evidence: `src/client-agent/internal/wazuh/install.go:112` · `src/api-gateway/internal/handlers/installers/join_install.sh.tmpl:553` · `src/api-gateway/internal/handlers/installers/agent_install.go:120` · `src/client-agent/internal/hostconfig/pam_sudo_eventlog.go:78` · `src/client-agent/internal/hostconfig/pam.go:422`
`src/client-agent/internal/wazuh/register.go` registers an **already-installed** agent with the Wazuh
manager and patches `ossec.conf` to point at it; registration is non-fatal and is skipped when no agent
is present. Where an agent does exist, enrollment and log forwarding work. Whether the Wazuh FIM module
monitors the adamance agent's own log paths (`/var/log/adamance/`) and alerts on tampering remains
unverified.

An earlier revision of this section cited `src/client-agent/internal/wazuh/install.go` as evidence that
adamance installed and configured the agent. That file was unreachable code, gated on a `wazuh_key` the
server never populated, and has been deleted. It never ran on any host, so the control it was cited as
evidence for was never delivered by that path. Recorded here because a threat model that cites
non-executing code as as-built evidence is worse than one that admits a gap.

**Finding:** TM-12 (LOW). Confirm FIM monitors adamance agent logs on managed hosts.
**Finding:** TM-12b (MED). This control depends on an operator-installed Wazuh agent. Either surface
per-host SIEM coverage so the gap is visible, or land the gateway-served pinned wazuh-agent package so
hosts obtain one automatically (backlog).

---

#### TMS-13 · NEEDS_RULING · Compromised host pulls sensitive policies it shouldn't see
**Required control:** OPA bundles are scoped per host group. Bundle requests authenticated with host cert.

**As-built:** 🔴 **REFUTED 2026-08-31. This row previously read "✅ CONFIRMED / Finding: NONE" and
that was false.** It is corrected in place rather than deleted, because a threat-model row that
recorded a control as *verified* when nothing implemented it is itself the most important finding
here: every later reader took it as an audit result.

**Re-measured 2026-09-22 at `ef276bcf`:** NEEDS_RULING. 🚨 The 2026-05-26 verdict was OVERSTATED, and a first re-measurement here said PARTIAL on the strength of `admit()` refusing callers without a host identity or with revoked enrolment, failing closed when the host registry cannot be read. That check is real but ORTHOGONAL: it decides who may pull, not what they receive. The required control is per-host-group SCOPING, and the code declines it in terms — `bundle.go:372-375` reads "⚖️ SCOPING IS A DIFFERENT, LARGER RULING AND IS DELIBERATELY NOT TAKEN HERE. The bundle's CONTENT is still fleet-wide; this only decides who may pull it." The agent builds one fixed path with no targeting parameter (`pull.go:196-200`) and the operational bundle still carries the fleet-wide host maps. ⇒ NEEDS_RULING rather than NOT_BUILT because the tree itself records the open decision — per-caller bundles versus stripping the maps — and that choice changes the TTL and revision model the agent depends on.
What is true: `src/client-agent/internal/bundle/pull.go` pulls over the host mTLS certificate, and
the agent verifies bundle signatures before applying. Both hold.

What is false: **there is no scoping of any kind.** `src/api-gateway/internal/bundle/bundle.go`'s
`ServeHTTP` selects a bundle with `switch path.Base(r.URL.Path)`; that switch chooses the bundle
*kind* (operational, compliance), never the *caller*. ⚠️ **Narrowed 2026-09-02:** the `bundle`
package now does call `HostIdentityFromContext` at `bundle.go` in `admit()`, which refuses a
caller whose certificate verifies but whose host is no longer enrolled. That decides **whether**
to serve, never **what** to serve, so the sentence this replaces (*"never called anywhere in the
`bundle` package"*) is no longer true while the claim it supported still is: the served bytes do
not depend on who asked. The agent could
not request a scoped bundle even if the server offered one: `pull.go` builds one fixed path and
sends no query parameter. The parenthetical "(path-based or query-parameter-based targeting)" above
described two mechanisms, neither of which exists.

**Finding:** 🔴 **OPEN; fleet-wide disclosure to any single enrolled host.** The operational
bundle carries fleet-wide maps: `deploy/dev/policy-data/host_group.json` is `{FQDN: host_group}`
and `host_tiers.json` is `{FQDN: approval_tier}`, both for **every** host. ⇒ root on any one
enrolled host, using that host's own legitimate certificate, reads every other host's FQDN, host
group and SSH approval tier. That is not privilege escalation; it is reconnaissance, and it is
precisely what this row exists to prevent.

⚖️ **The fix is a ruling, not a patch.** Per-caller bundles mean per-caller signing and cache
keys, which changes the TTL and revision model the agent relies on. The narrower alternative is to
stop shipping fleet-wide host maps in a bundle every host can read. Recorded here rather than
decided.

⛔ **Do not re-close this row on the strength of the mTLS check.** Authenticating the caller and
scoping the response are different controls; conflating them is how this row came to say
CONFIRMED.

---

#### TMS-14 · PARTIAL · Compromised host abuses its sudo rights to escalate
**Required control:** sudo rules are scoped narrowly. Sudo invocations are audit-logged centrally and
trigger alerts on anomaly.

**As-built:** ⚠️ DESIGN-ONLY; the sudo rules themselves are in the OPA policies (`policies/`), which
were not reviewed in this pass. The agent's `hostconfig/sssd.go` configures SSSD which reads HBAC/sudo
rules from FreeIPA. The audit emission from sudo events depends on Wazuh's syslog/auditd integration.

**Re-measured 2026-09-22 at `ef276bcf`:** PARTIAL. 🚨 The 2026-05-26 verdict was OVERSTATED. Both halves of the row are wrong, in opposite directions. Narrow scoping is falsified on a DEFAULT install: migration 0044 seeds 15 named sudo rules - verified by count and by name, including `/bin/dd *`, `/usr/bin/shred *` and `/bin/drop_database` - startSudoReconciler is called from main.go:2342 with no features.Enabled anywhere between the host-group-policy init and that call (verified over lines 2320-2345), and the five management routes plus the console page mount only when the segmentation feature is on, which both shipped manifests ship off. So those allows are written toward FreeIPA while no operator surface lists them, which makes TM-13's INFO severity an understatement of the risk. The audit half is the reverse: the row says sudo audit emission is outside the agent's scope, and the agent now configures it - the sudoers event-log drop-in called from the PAM install, plus auditd rules and pam_tty_audit, drained to the gateway by a packaged unit. That capture still installs only at the enrolment moment with the fleet opt-in seeded false, and no shipped Wazuh or SIEM rule fires on a sudo anomaly - a case-insensitive search for sudo across the dev Wazuh config, the SIEM compose and the SIEM install step returns nothing - so 'trigger alerts on anomaly' is unmet. Has it ever run: The sudo reconciler starts on any boot where a pool and a FreeIPA write client exist, which is the default production shape, so the seeded rules are reachable by default - the call site and the absent gate were read, but no live push into FreeIPA was watched, so that specific half is inferred rather than observed. Sudo command capture has run in the dev prod-host container. No sudo-anomaly alert rule exists anywhere, so that part of the control has never run. Evidence: `src/api-gateway/internal/db/migrations/0044_host_group_policies.sql` · `src/api-gateway/cmd/server/main.go:2342` · `src/api-gateway/cmd/server/main.go:6593` · `src/client-agent/internal/hostconfig/pam_sudo_eventlog.go:63` · `src/client-agent/internal/hostconfig/pam.go:422`
**Finding:** TM-13 (INFO); sudo policy scoping is as-designed (OPA + FreeIPA HBAC). Audit of sudo
events depends on Wazuh syslog/auditd configuration on managed hosts, which is outside the adamance
agent's scope (it's host OS configuration).

---

#### TMS-15 · PARTIAL · Stolen user TGT used from another host
**Required control:** Tickets bound to addresses where possible. Short ticket lifetime (8h default;
1h for admin principals). Renewal requires re-auth past max renewable lifetime (24h).

**As-built:** ⚠️ NOT VERIFIED IN CODE. Kerberos configuration lives in SSSD config (`src/client-agent/internal/hostconfig/sssd.go`)
and FreeIPA's KDC config. The specific `krb5_lifetime` and `max_life` per-principal settings were
not confirmed in this pass.

**Re-measured 2026-09-22 at `ef276bcf`:** PARTIAL. ⚠️ The 2026-05-26 verdict was UNDERSTATED — the tree does more than the row admitted. The 8h / 24h half IS in the tree and the row denies it: src/client-agent/internal/hostconfig/sssd.go:73-75 emits krb5_lifetime = 8h, krb5_renewable_lifetime = 24h, krb5_renew_interval = 2h, mirrored in configs/sssd/sssd.conf.template:55-56 and bastion.go:93-94. But the SAME agent writes /etc/krb5.conf with ticket_lifetime = 24h and renew_lifetime = 7d (ipaclient.go:70-71), so any interactive kinit on a managed host gets 3x the required 8h default and 7x the required 24h renewable ceiling. Address binding is absent tree-wide: five terms (noaddresses / no_addresses / addressless / krb5_use_kdcinfo / max_renewable_life) return nothing outside docs, and ipaclient.go:69 sets forwardable = true, the opposite posture. No per-principal 1h admin policy exists anywhere: krbmaxticketlife / krbmaxrenewableage / krbtpolicy return zero hits and the only 1h matches are JIT grant durations in README.md:472 and src/lac/cmd/lac/jit.go:64. Has it ever run: NOT ESTABLISHED. sssd.go:126 renders the template inside a config-apply function with a DryRun branch at :129, but the exported caller was not found - a grep for RenderSSSDConf / SSSDConf / WriteSSSD outside bastion.go returned only the bastion variant, so it cannot be said that a real host has ever had these lifetimes written. The krb5.conf half has the same open question. ⇒ None owns Kerberos ticket lifetime. An open gap owns the clock every lifetime and freshness check trusts, and names Kerberos ticket validity first in its list. Another open gap owns a different krb5.conf defect (the gateway mount hardcoded to DEV.LOCAL). Evidence: `src/client-agent/internal/hostconfig/sssd.go:73` · `src/client-agent/internal/hostconfig/ipaclient.go:70` · `src/client-agent/internal/hostconfig/ipaclient.go:69` · `configs/sssd/sssd.conf.template:55` · `src/client-agent/internal/hostconfig/bastion.go:93`
**Finding:** TM-14 (LOW). Kerberos ticket lifetime enforcement should be verified against the actual
`krb5.conf` or SSSD domain configuration generated by the agent.

---

### Policy bypass (A3)

#### TMS-16 · PARTIAL · User exploits a gap in a policy that wasn't `default deny`
**Required control:** All OPA decision documents and FreeIPA HBAC rules are default-deny. Verified by
policy unit tests in CI.

**As-built:** ⚠️ PARTIALLY REVIEWED. Two bugs found and fixed during this pass. See TM-15 findings below.

**Re-measured 2026-09-22 at `ef276bcf`:** PARTIAL. 🚨 The 2026-05-26 verdict was OVERSTATED. The OPA half holds and is broader than the row's five reviewed policies. Every non-helper decision policy carries a deny-shaped default: measured across 23 non-compliance rego files, policies/api/authz.rego:26 (default decision allow false), :3874, policies/api/security.rego:29-68 (six), policies/governance/require_approval.rego:35, policies/ssh/access.rego:21, bastion_access.rego:23, bastion_connect.rego:46, policies/authz/cross_forest.rego:47, policies/fim/policy.rego:19, policies/firewall/host.rego:39. The zero-default files are helpers with no decision head (policies/lib/* and policies/segmentation/effective.rego:13, a data alias). Two are default-not-required rather than default-deny: source_pin.rego:20 and ssh_approval.rego:20 both default to required false. THE HBAC HALF OF THE REQUIRED CONTROL FAILS: src/api-gateway/internal/config/config.go:661 states adamance does NOT manage HBAC at install time and FreeIPA ships with allow_all, i.e. any user to any host to any service; managed_ssh_groups is absent from configs/api-gateway/api-gateway.prod.yml, and config.go:677 says empty or absent managed_ssh_groups makes the harden and disable-allow_all paths unavailable. Nothing guards default-deny as a property - the only hit over scripts/ Makefile tests/ is a comment at scripts/verify-bundle-data.sh:68. Has it ever run: HBAC hardening has never run outside the API. Five terms over deploy/, scripts/, Makefile and the runbooks (hbac.harden / hbac allow-all / hbac_harden / disable allow_all) hit only the multi-tenant-setup runbook (a runbook for a deleted feature) and a comment in scripts/triage-status-drift.sh:34. No installer, drill or packaging step calls it. The row's Verified by policy unit tests in CI is also unmet: the policies-build workflow's last five runs are ALL failure, newest 2026-08-06 (gh run list). The 116 rego test files do run locally via make test-policies (Makefile:1162-1168). ⇒ NO open gap tracks HBAC default-deny, which is itself a finding. An open row records the hostcategory=all consequence only in passing while discussing the SSH CA. Another open row owns the missing bad-policy test. Evidence: `policies/api/authz.rego:26` · `policies/api/security.rego:29` · `policies/ssh/source_pin.rego:20` · `policies/ssh/ssh_approval.rego:20` · `src/api-gateway/internal/config/config.go:661`
**TM-15 Findings, core policies reviewed:**

Policies confirmed with `default deny` from the start:
- `adamance.api.authz`: ✅ Default deny correct. Every operation has explicit allow rules.
- `adamance.enrollment.allowed`: ✅ Default deny correct. Super-admin allow, enrollment operator allow,
  host-already-enrolled deny, then explicit deny.
- `adamance.ssh.access`: ✅ Default deny correct. Super-admin allow, group-allowed SSH, then explicit denies
  for principal mismatch, outside access window, no group match.
- ~~`adamance.sudo.conditional`~~: **REMOVED** (sudo policy comes from FreeIPA); it was a placeholder nothing queried. Historic review below. ✅ Default deny correct. Super-admin allow, conditional rules, explicit denies
  for MFA stale, no MFA, approval-required, command not matched.
- `adamance.lib.decision`: ✅ `combine_decisions` correctly handles `allow=true` when all sub-decisions allow.
  The lib has no `default deny` of its own (it's a helper, not a policy package).

**Bug 1 (FIXED): `adamance.lib.decision.concat` was undefined on nested arrays**

`combine_decisions` uses:
```rego
all_reasons := concat(", ", [d.reasons | d := decisions[_]])
```
When `decisions = [{"allow": true, "reasons": []}]`, the comprehension produces `[[]]`.
`concat(", ", [[]])` matched no rule and returned `undefined`, making `combine_decisions` return
`undefined` for perfectly valid all-allow inputs with no reasons.

Fix: added explicit overloads for single-element arrays in `concat`:
```rego
concat(sep, [[]]) = ""
concat(sep, [[h]]) = h
concat(sep, [[h, tail...]]) = ...
```

Regression tests added to `policies/lib/decision_test.rego`.

**Bug 2 (FIXED): `adamance.sudo.conditional.subject_in_rule_groups` had inverted logic**

The helper was:
```rego
subject_in_rule_groups(rule) if {
    some sg in rule.subject_groups
    not sg in input.subject.groups
}
```
`some sg in X; not sg in Y` means "∃g∈X: g∉Y"; there exists a rule group not in the subject's groups.
This is the **opposite** of the intended logic. The correct expression for "some of the subject's groups
is in the rule's groups" is:
```rego
subject_in_rule_groups(rule) if {
    some sg in input.subject.groups
    sg in rule.subject_groups
}
```

Impact: With the bug, a subject IN a rule's allowed groups would get `subject_in_rule_groups = false`,
causing the matched rule to be silently ignored. The policy would then fall through to the
"command not in any sudo rule" deny path, denying legitimate access incorrectly.

The existing test `test_subject_group_mismatch_denied` accidentally masked this bug: it tested
a subject NOT in any rule's groups, which the buggy logic returned `true` for, and then the
policy's final "command not matched" deny path produced the right outcome for the wrong reason.

Fix: corrected the `some` direction. Added `test_subject_in_rule_groups_should_match` to
`policies/sudo/conditional_test.rego` that specifically exercises the corrected direction and
asserts an `allow` outcome.

**Remaining review needed:**
- `policies/firewall/host.rego`: ✅ Reviewed. `default deny` correct. Single unconditional generation
  rule produces a full ruleset for any valid host group. Drop-by-default base rules, management-CIDR SSH
  fallback, agent connectivity preserved. No issues found.
- `policies/fim/policy.rego`: ✅ Reviewed. `default deny` correct. Single unconditional generation rule
  merges global FIM defaults with per-group additions via `array.concat`. No issues found.
- `policies/data/`: ✅ Data files (global.json, group data). Not authorization policy; reviewed as part of
  data schema. `step_up_mfa_max_age_seconds: 300` confirmed correct.
- `policies/governance/`: ✅ Scaffold only per its own README. No decision rules implemented yet.
- `policies/compliance/cis/`: 80+ files. Not reviewed in this pass (CIS benchmark audit, separate from
  default-deny authorization review).

---

#### TMS-17 · PARTIAL · User races between policy update and enforcement
**Required control:** Local OPA decisions on the host. Bundle TTL ≤ 60s for security-critical policies.
Push-on-change via webhook for highest-impact policies.

**As-built:** ⚠️ PARTIAL.

**Re-measured 2026-09-22 at `ef276bcf`:** PARTIAL. 🚨 The 2026-05-26 verdict was OVERSTATED. The serving half is real: scripts/build-policies.sh has a critical target (lines 42, 119, 139, 188) producing bundle.critical.tar.gz, and src/api-gateway/internal/bundle/bundle.go:217-218 defaults CriticalMaxAge to 60s with CriticalBundlePath plumbed at :223-226, :240 and :314. NOTHING REQUESTS IT. Searching src/client-agent/internal/bundle/ and src/client-agent/internal/opa/ for critical returns zero hits, while the same pathspec returns the two paths the agent does fetch: pull.go:154 defaults to /api/v1/policies/bundle.tar.gz and :48-50 names /api/v1/policies/compliance-bundle.tar.gz as the only second fetcher. So the 60s TTL is served to no consumer, and the host's local OPA polls the 300s bundle on a 60s ticker (pull.go:55, :144-145, :326). Push-on-change has no implementation of any kind: a case-insensitive webhook grep over both bundle packages matches no file. The row's own closing sentence already concedes the TTL is a staleness bound and not a revocation bound. Has it ever run: The critical bundle is only produced by make build-policies --target critical or the policies-build workflow, whose last five runs are all failure, newest 2026-08-06. No evidence was found that any host has ever received a critical bundle, and no consumer exists to receive one. The 60s TTL code path in ServeHTTP has unit coverage but a live request to bundle.critical.tar.gz was not traced. Evidence: `src/api-gateway/internal/bundle/bundle.go:217` · `src/api-gateway/internal/bundle/bundle.go:226` · `src/client-agent/internal/bundle/pull.go:154` · `src/client-agent/internal/bundle/pull.go:48` · `src/client-agent/internal/bundle/pull.go:326`
- Local OPA on host: ✅ CONFIRMED. `src/client-agent/internal/opa/manager.go` runs local OPA.
- Bundle TTL ≤ 60s: The bundle config (`src/api-gateway/internal/config/config.go`'s `BundleConfig.MaxAgeSec`)
  defaults to 300s (5 minutes). The design says ≤ 60s for security-critical policies. Whether this is
  enforced in the bundle server or in policy was not verified.
- Push-on-change webhook: ❓ NOT VERIFIED. The OPA bundle server may support webhook invalidation
  (`--bundle.name.webhook-trigger`) but this was not confirmed.

**Finding:** TM-16 (MEDIUM). Bundle TTL default (300s) exceeds the ≤60s requirement for security-critical
policies stated in the threat model. Either the design needs to be updated or the implementation needs
a per-bundle TTL configuration that enforces ≤60s for SSH/sudo/admin policies.

**Resolution:** ⚠️ PARTIALLY RESOLVED (2026-05-27, orchestrator review).

`CriticalMaxAgeSec` added to `BundleConfig` and `CriticalMaxAge`/`CriticalBundlePath` added to the
bundle server `Config`. `ServeHTTP` now applies ≤60s TTL (configurable, default 60s) for requests to
`/policies/bundle.critical.tar.gz` (security-critical policies: sudo, firewall, admin-group), while
the default bundle serves at 300s TTL. Mechanism is correctly implemented.

**Resolution:** ✅ RESOLVED (2026-07-11). ⚠️ **Corrected 2026-09-04: the paragraph below was left
standing as a current gap 55 days after it closed.** It read: "**Remaining gap (V1 follow-up):**
`bundle.critical.tar.gz` is never produced by `scripts/build-policies.sh`; the `critical` target does
not exist. The TTL mechanism exists but has no artifact to serve. Additionally, the YAML config field
`CriticalBundleDir` is not plumbed into `CriticalBundlePath` in the bundle server." Both halves are
built: `scripts/build-policies.sh` has a `critical` target, `release.yml` and `policies-build.yml`
produce the artifact, and `bundle.go` plumbs `CriticalBundlePath` and `CriticalMaxAge`. `policies/sudo`
was dropped from the critical sources because sudo policy comes from FreeIPA, and the build now fails
if a listed critical source is missing. The TTL is a staleness bound and not a revocation bound; how
fast a withdrawn permission actually stops being enforced is the revocation-convergence row in the
cross-cutting section, and it is not measured.

---

#### TMS-18 · NOT_BUILT · Policy change introduces a vulnerability that ships before review
**Required control:** Policy changes go through git → CI (rego unit tests, opa eval against fixtures) →
review (one approver minimum; two for policies touching admin groups or root access) → signed bundle build.

**As-built:** ✅ CONFIRMED. CI pipeline added in this pass.

**Re-measured 2026-09-22 at `ef276bcf`:** NOT_BUILT. 🚨 The 2026-05-26 verdict was OVERSTATED, and a first re-measurement here said PARTIAL on the strength of the workflow files existing. They do: `release.yml` defines a build-policies job running regal lint and opa test before a signed build, and the release job depends on it. ⛔ IT HAS NEVER RUN, AND COULD NOT SUCCEED IF IT DID. Measured directly rather than inferred: GitHub Actions is disabled at the repository level (`gh api …/actions/permissions` → `enabled: false`) and there are 0 published releases, so no policy change has ever passed through this gate. And `release.sh:619` exports `REQUIRE_PROD_KEY=true`, which is a hard failure without a signing key that has never been created — so enabling Actions today would fail the job at signing. Adding workflow files is not a control that has ever reviewed anything.
The `release.yml` now includes a `build-policies` job (Job 0b) that runs `regal lint`, `opa test`,
`opa eval` against fixtures, `opa build` with signing, and uploads the bundle to the GitHub release.
The `release` job now depends on `build-policies`. The local `make verify-policies-bundle` target
was already present and functional.

**Finding:** TM-17 (INFO). The CI pipeline for policy builds was not verified end-to-end in this pass.
Recommend a dedicated review of `.github/workflows/release.yml`'s policy build job.

**Resolution:** ✅ RESOLVED (2026-05-27, go-coder-policy). Added `build-policies` CI job to
`release.yml`.

---

### Control plane compromise (A4)

#### TMS-19 · PARTIAL · Operator with API access silently escalates a user
**Required control:** All write operations to FreeIPA and OPA are logged to Wazuh tagged with operator
identity. Logs are write-only from the operator's perspective.

**As-built:** ✅ CONFIRMED (design), ⚠️ NOT VERIFIED (Wazuh log sink configuration).

**Re-measured 2026-09-22 at `ef276bcf`:** PARTIAL. 🚨 The 2026-05-26 verdict was OVERSTATED. The emitter is real and wired: src/api-gateway/cmd/server/main.go:455 reads WAZUH_INDEXER_URL, :466 constructs the WazuhEmitter, :475 falls back to StdoutEmitter. But a fresh production install most likely lands on stdout: deploy/setup/install.sh:830 writes WAZUH_INDEXER_URL only inside an elif that requires the dev indexer container to be inspectable AND two password files under deploy/dev/secrets/ to exist - dev paths inside the production installer - and the else branch at :839 says recordings ingest stays disabled, stdout audit emitter. Worse for the required control's word ALL: The chain-visibility gap (marked FIX THIS FIRST) establishes that the chain only sees what goes through the gateway, so a direct Postgres write, an LDAP modify against the directory, or a Keycloak admin call emits no entry at all - and an LDAP modify is exactly a write operation to FreeIPA by the A4 insider this row is written for. The attribution gap establishes that the operator identity on an event is a field the producer fills in, so tagged with operator identity is asserted, never proved. Has it ever run: NOT ESTABLISHED for the Wazuh path on a real install. The installer branch was read, not a run of it, and no audit event was observed arriving at an indexer. policies/data/features.json:5-7 has recording true, wazuh false, wazuh_fim false, so the WAZUH_INDEXER_NEEDED precondition is satisfied by recording alone - but the two dev secret files the elif also requires are the deciding condition and it was not checked whether a fresh install creates them. Evidence: `src/api-gateway/cmd/server/main.go:455` · `src/api-gateway/cmd/server/main.go:475` · `deploy/setup/install.sh:830` · `policies/data/features.json:5`
Every handler in `src/api-gateway/internal/handlers/` calls `auditFn()` with the operator identity from
the session. The `src/common/audit` package formats audit events consistently. Whether these events
reach Wazuh (vs. stdout only in dev mode) depends on the deployment's log routing configuration, which
was not reviewed.

**Finding:** TM-18 (RESOLVED); `WazuhEmitter` confirmed routing to Wazuh indexer via OpenSearch bulk API. Both dev stack and the single-host package wire `WAZUH_INDEXER_URL`. StdoutEmitter fallback when not configured; no silent audit drop.

---

#### TMS-20 Compromised operator account changes policy
**Required control:** Sensitive operations require fresh MFA (step-up within last 5 minutes). High-impact
policy changes require a second approver via the UI.

**As-built:** ✅ CONFIRMED for MFA step-up. ✅ DUAL CONTROL BUILT AND FAIL-CLOSED (2026-08-28).

⚠️ **Corrected 2026-09-04: this paragraph opened "The `authz.RequireMFA()` middleware enforces fresh
MFA for sensitive endpoints" and there is no such middleware.** The only `RequireMFA` in the tree is
`src/api-gateway/internal/handlers/users/handler.go:1624`, an admin action that forces a user to enrol
OTP, routed at `src/api-gateway/cmd/server/main.go:4553`, which is a different thing entirely. Step-up
is enforced by policy, not by a per-route Go middleware: the `check_user_with_mfa_stepup` family in
`policies/api/authz.rego` gates 79 operations, and a factor older than `step_up_mfa_max_age` (default
300s, `policies/api/authz.rego:3408`) returns the `require_mfa_age_max_seconds` obligation
(`policies/api/authz.rego:2582`). The same correction was already made at the step-up row above on
2026-09-01 and was not carried down to here, which is exactly the failure this document's own reading
rule exists to prevent. The UI has an Approvals
inbox (`web/admin-ui/src/pages/Approvals.tsx`). The backend gate is the OPA decision
`governance.require_approval` in `policies/governance/require_approval.rego`, evaluated by
`src/api-gateway/internal/handlers/policy/handler.go` on `POST /api/v1/policies/publish`
(route registered at `src/api-gateway/cmd/server/main.go:4819`). ⚠️ **Corrected 2026-09-02: this read "It requires 2 distinct non-self approvers" and that is wrong.** `policies/governance/require_approval.rego:42-48`: the default `second_approver: false` requires ONE distinct approver, which is two-person control counting the requester; `true` requires two, which is three-person control. The requester is never counted either way. Original text follows, corrected: it requires the configured number of distinct non-self
approvers and forbids self-approval, and it refuses the publish when the rule is not loaded rather
than skipping the check.

**Finding:** TM-19 (MEDIUM). The second-approver requirement for high-impact policy changes should be
verified in the OPA policy (`adamance.api.authz`) or in the handler for the policy publish endpoint.

**Resolution:** ✅ RESOLVED (2026-06-11, commit `b7051bcc`). Superseded the 2026-05-27 assessment below.

⚠️ **The paragraph this replaced was wrong for 78 days and said the opposite.** It claimed the
governance policy framework and the publish handler "do not exist" and deferred TM-19 to V1.5. Both
had landed. The rule it named, `adamance.governance.require_second_approver`, never compiled under
opa 0.69, which left the publish gate FAIL-OPEN; `b7051bcc` retired it, routed policy-publish through
`governance.require_approval`, and `src/api-gateway/internal/handlers/policy/handler.go:365` now fails
CLOSED on a missing rule. See `policies/governance/README.md`, which carried the same dead name.

---

#### TMS-21 Backup tampering
**Required control:** Backups signed and encrypted with a key no operator account holds. Restore requires
presenting the offline key.

**As-built:** ⚠️ RUNBOOK EXISTS, KEY MANAGEMENT NOT VERIFIED.

A restore runbook exists and references the offline backup key. The signing ceremony
is documented. The actual key storage location (USB in safe, HSM, etc.)
is an operational decision not captured in code. This is acceptable; the runbook correctly states
the requirement.

**Finding:** NONE. Operational gap, not an implementation gap.

---

#### TMS-22 Operator pivots from API gateway host to FreeIPA host
**Required control:** Control plane components run on separate hosts or at minimum separate user namespaces.
API gateway service account has no SSH access to other control plane hosts.

**As-built:** ⚠️ NOT VERIFIED; this is a deployment topology control.

The single-host deployment necessarily runs all control plane components on the same host. The
security architecture document acknowledges this and the multi-node topology (V1.5) is where this
control becomes meaningful. For single-host, the finding is documented.

**Finding:** TM-20 (INFO). This control is not enforceable in the single-host topology. It applies
to HA/multi-site. The threat model should note this explicitly (single-host exemption documented).

**Resolution:** ✅ RESOLVED; single-host exemption note added (2026-05-27, red-team).

This control applies to HA/multi-site topologies only. In single-host, the operator and the control plane share the same host; this control is not enforceable. The V1 deployment guide documents this as a known limitation.

⚠️ **Corrected 2026-09-26 (external review): the exemption above is withdrawn, because the control it exempts is possible on one host.** It read "In single-host, the operator and the control plane share the same host; this control is not enforceable." The row's own required control already says "or at minimum separate user namespaces", and separate user namespaces, separate service identities, no shared administrative sockets, and per-component mounts, capabilities, secrets and network access are all achievable on a single host. Compromise of the shared host's root or kernel is a separate, common-mode risk and does not exempt the component-level control. The requirement applies to every topology. **Status: NOT MEASURED** for single-host isolation.

---

### Cryptographic baseline

#### TMS-23 TLS 1.3 only
**As-built:** ⚠️ PARTIAL CONFIRMATION.

`src/api-gateway/internal/config/config.go` TLS section was not reviewed in this pass. The design
states TLS 1.3 only. The Go `crypto/tls` library is configured via `tls.Config` in main.go. The
minimum version setting was not confirmed in this pass.

**Finding:** TM-21 (RESOLVED). Confirmed: `src/common/mtls/tlsconfig.go` sets `MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13`. The mTLS server uses `BuildServerConfig`. TLS 1.2 is rejected. No changes required. See **TM-21** HANDOFF.

#### TMS-24 Internal service clients use TLS 1.2
**As-built:** ✅ RESOLVED (2026-07-11). ⚠️ **Corrected 2026-09-04: this read "❌ VIOLATION" and stayed
that way after the violation was fixed.** There is no remaining `tls.VersionTLS12` in
`src/api-gateway` or `src/wazuh-bridge` (31 `MinVersion: VersionTLS13`, zero `VersionTLS12`), and the
last residual, the three client-agent join-bootstrap configs in
`src/client-agent/internal/enroll/join.go`, was raised to `tls.VersionTLS13` on 2026-07-11. The
original finding follows unaltered, because the file list is what made it findable.

The api-gateway server correctly enforces TLS 1.3 via `src/common/mtls/tlsconfig.go` (TM-21). However, multiple internal service-to-service clients still use `tls.VersionTLS12`:

| File | Line | Client |
| ---- | ---- | ------ |
| `src/api-gateway/internal/sshca/client.go` | 75 | SSH CA client |
| `src/api-gateway/internal/handlers/sshca/crl.go` | 61 | CRL fetcher |
| `src/api-gateway/internal/integrations/wazuh/client.go` | 64 | Wazuh API client |
| `src/api-gateway/internal/ipa/rpc_client.go` | 34 | FreeIPA RPC client |
| `src/api-gateway/internal/ipa/ldap_client.go` | 75, 142 | FreeIPA LDAP client |
| `src/api-gateway/cmd/server/main.go` | 341 | mTLS client (Wazuh manager) |
| `src/wazuh-bridge/internal/wazuhapi/client.go` | 65 | Wazuh API client (wazuh-bridge) |

This is a **cryptographic baseline violation**. The threat model (§ Cryptographic baseline) requires TLS 1.3 only for all internal communication.

**Finding:** TM-23 (MEDIUM). Internal service clients use `tls.VersionTLS12` instead of `tls.VersionTLS13`. A downgrade attack or weak TLS configuration on any internal service-to-service connection could go undetected with TLS 1.2.

**Remediation:** Update all internal service clients to use `tls.VersionTLS13`. The `src/common/mtls/tlsconfig.go` `BuildClientConfig()` already enforces TLS 1.3; all clients should use it or equivalent configuration.

#### TMS-25 · PARTIAL · JWT: EdDSA only
**As-built:** ✅ CONFIRMED.

**Re-measured 2026-09-22 at `ef276bcf`:** PARTIAL. 🚨 The 2026-05-26 verdict was OVERSTATED. The row's cited facts still hold exactly: session.go:268 signs with jwt.SigningMethodEdDSA and session.go:587 refuses any other method, so every adamance-minted session JWT is EdDSA and HMAC is rejected. But "EdDSA only" is not true of the tree's JWT handling as a whole, and the two exceptions are on live paths rather than in tests: handlers/auth/jwks.go validates the OIDC provider's tokens with an RSA-only keyfunc and jwt.WithValidMethods(RS256 / RS384 / RS512), wired into KeycloakHandler and personal_oauth - the browser sign-in path - and sshca/client.go:140 signs a provisioner JWT with jose.ES256 for step-ca. Neither accepts HMAC or "none", so the row's second sentence survives tree-wide; what fails is the first, and the baseline text explicitly says deviation requires explicit documentation, which this row instead forecloses with a bare CONFIRMED. Has it ever run: The EdDSA signer and verifier are on the session mint and verify path, and the RS256 verifier is reached through KeycloakHandler.jwks() and personal_oauth, so both run on any sign-in. That is from call sites and struct wiring, not from an executed login - no auth flow was run. The ES256 step-ca provisioner path depends on an SSH CA that a production install never starts, so it may never have run in production. ⇒ None - no open gap covers JWT algorithm scope. The nearest row is about FIPS-validated cryptographic modules rather than algorithm choice, so this is an unregistered deviation. Evidence: `src/api-gateway/internal/session/session.go:268` · `src/api-gateway/internal/session/session.go:587` · `src/api-gateway/internal/handlers/auth/jwks.go:143` · `src/api-gateway/internal/handlers/auth/jwks.go:189` · `src/api-gateway/internal/handlers/auth/keycloak.go:111`
`src/api-gateway/internal/session/session.go` line 63:
```go
token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
```
Line 95:
```go
if t.Method != jwt.SigningMethodEdDSA {
    return nil, ErrInvalidAlgorithm
}
```
HMAC algorithms explicitly rejected. This is the correct implementation.

#### TMS-26 Password hashing: Argon2id
**As-built:** ⚠️ NOT VERIFIED IN CODE.

The password hashing for user passwords in FreeIPA is handled by FreeIPA (MIT Kerberos / Dogtag).

⚠ Corrected 2026-09-01: this passage said `configs/crypto.yaml` "was not reviewed in this pass", which reads as if
the file exists. It has never existed under any name, so there was nothing to review. The absence finding is also
stronger than "not directly referenced": `golang.org/x/crypto/argon2` is in no `go.mod` and is imported by no `.go`
file in the tree. Outside documentation the only `argon2` strings are a shell placeholder
(`deploy/freeipa/phases/D-first-admin.sh`), the `laRecoveryCodeHash` schema attribute
(`deploy/freeipa/schema/adamance-schema.ldif`), and a quarantined skeleton test whose own stub hashes with SHA-256
(`src/common/security/security_test.go`, build tag `security_skeleton`). Argon2id is still specified in eight
documents, including this one.

**Finding:** TM-22 (RESOLVED). Audit confirms: no direct password storage in `src/api-gateway/`. All auth delegates to FreeIPA. No bcrypt, scrypt, or argon2 usage found. Compliant by design. See **TM-22** HANDOFF.

---

## Open decisions

| ID | Decision | Proposed direction | Owner | Status |
| --- | --- | --- | --- | --- |
| TM-01 | HA model for FreeIPA | Multi-master replication across 2+ nodes; documented failover runbook ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** An `ipa-replica` service exists in the HA overlay and a failover runbook exists, so the documented half is real. What is missing is the replication itself ever being established: `deploy/docker-compose.ha.yml:51` states plainly that "The replica-install procedure is an OPERATOR step, not something this file performs", and the service sits behind the `ha-freeipa` profile so a default compose never starts it. The HA stack has never been installed here and only the API plane is pooled. Database failover is tracked as a separate open gap. Evidence: `deploy/docker-compose.ha.yml:51` · `deploy/docker-compose.ha.yml:459` | - | **PARTIAL** |
| TM-02 | Where does the OPA bundle live and how is it served? | Built in CI, signed offline, served by the API gateway over mTLS, cached locally on each agent ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The critical bundle is served and pulled over mTLS with signature verification. ⚠️ Citation corrected: serving is `bundle.go:354-356` / `:397`, not `:217-226`, which is config DEFAULTING (`CriticalMaxAge`, `CriticalBundlePath`). The claim was true of the file and false of the lines first cited. Evidence: `src/api-gateway/internal/bundle/bundle.go:354` · `src/api-gateway/internal/bundle/bundle.go:397` · `src/client-agent/internal/bundle/pull.go:1` | - | **PARTIAL** |
| TM-03 | Audit log retention and immutability | 90 days hot in Wazuh indexer; 1 year cold in object storage with object lock ⚠️ **Re-measured 2026-09-23 on the audit SIEM retention change, the change that adds `src/api-gateway/internal/handlers/recordings/audit_retention.go`; its branch was rebased before merging, so no branch SHA is cited.** The in-indexer half is wired: the ISM policy `adamance-audit-retention` is installed against the `adamance-audit-*` indices before the gateway's first audit write and re-asserted hourly, and an audit index whose retention the hourly sweep cannot vouch for (among them: no policy it could attach, another policy, a failed ISM action) is counted on `adamance_audit_indices_retention_not_in_force`. The gateway still starts when it cannot reach the indexer or may not install the policy, and says so on `adamance_audit_retention_policy_installed` and the `AuditRetentionPolicyMissing` alert; in that path only a 400 from the indexer to the policy or the index template stops it starting (a configured `audit.siem_retention_days` outside 30 to 3650 stops it earlier, at config load). It keeps each daily index in the indexer for `audit.siem_retention_days` + 1 days (366 by default, read-only from day 30) rather than 90, because the cold tier that would hold the rest of the year is not built. The 1-year cold object-lock half is design-only and self-declared as such: The audit-immutability design scores "Retention with object-lock" as **No (design only)** and append-only as **No** with "no object-lock"; `src/api-gateway/internal/handlers/compliance/auditstate.go:50` calls WORM object-lock V1.5. Evidence: `src/api-gateway/cmd/server/main.go:553-589` · `src/api-gateway/internal/handlers/recordings/audit_retention.go` · `src/api-gateway/internal/handlers/compliance/auditstate.go:50` | - | **PARTIAL** |
| TM-04 | Break-glass procedure for total directory loss | Offline-encrypted root credentials in a sealed envelope; procedure documented (resolved). Remaining gap is only the operational runbook copy. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The gap the row names as the only one remaining — the operational runbook copy — is CLOSED: a break-glass runbook exists, and break-glass code exists at `src/api-gateway/internal/handlers/admin/emergency.go`. But BOTH of the row's citations are dead: the cited break-glass document does not exist, and the governance document's break-glass entry is the approval-inbox UI, not break-glass — while the governance document still calls the runbook "to be written". The mechanism also still pages from the control plane it exists to survive and its SSH fallback file is never created by anything. Break-glass is also absent from the first-run checklist. | - | **PARTIAL** |
| TM-05 | MFA enrollment flow and recovery | TOTP + WebAuthn; recovery codes printed once; admin can reset MFA only with second-approver MFA challenge ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Admin MFA reset IS dual-controlled, but ⛔ NOT where an earlier measurement said: `authz.rego:767-768` is a COMMENT and it says the opposite — "the blanket gate must NOT emit a dead approval_required obligation". The rego rule at `:771` is `check_user_with_mfa_stepup_or_auditor_deny("user.reset_mfa")`. The approval routing lives only in the handler (`users/handler.go:1584`). WebAuthn enrolment is absent. Recovery codes are documentation only — the secrets-and-PKI document specifies Argon2id and nothing implements it. Evidence: `src/api-gateway/internal/handlers/users/handler.go:1584` · `policies/api/authz.rego:771` | - | **PARTIAL** |
| TM-06 | Rate limiting on `/oauth/token` endpoint | ✅ RESOLVED: `OAuthTokenRateLimiter` (5 req/min per IP+UA) added to `ratelimit.go`. `OAuthTokenRateLimitMiddleware` wired in `main.go`. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** `OAuthTokenRateLimiter` is defined at `src/api-gateway/internal/middleware/ratelimit.go:356-390` as a per-IP token bucket, and it is wired on the router at `src/api-gateway/cmd/server/main.go:3360` via `middleware.OAuthTokenRateLimitMiddleware(oauthTokenRL, emitAny, logger)`, constructed at `:599`. Both the definition and the call site check out. Evidence: `src/api-gateway/internal/middleware/ratelimit.go:356` · `src/api-gateway/internal/middleware/ratelimit.go:384` · `src/api-gateway/cmd/server/main.go:599` · `src/api-gateway/cmd/server/main.go:3360` | api-gateway | **BUILT** |
| TM-07 | Refresh token IP + User-Agent binding | ✅ RESOLVED: `RefreshTokenStore` in `session.go` enforces IP+UA binding. Single-use. Wired into `auth.TokenHandler`. Security events emitted on IP/UA mismatch. Integration tests in `src/api-gateway/internal/handlers/auth/token_integration_test.go`. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** `RefreshTokenStore` at `src/api-gateway/internal/session/session.go:938-951` documents and implements IP + User-Agent binding with single use, and it is constructed in production at `src/api-gateway/cmd/server/main.go:565-570` — Postgres-backed via `NewRefreshTokenStoreWithBackend` when a pool exists, in-memory otherwise — with a GC loop at `:6549`. The integration test the row cites was not re-run. Evidence: `src/api-gateway/internal/session/session.go:938` · `src/api-gateway/internal/session/session.go:951` · `src/api-gateway/cmd/server/main.go:565` · `src/api-gateway/cmd/server/main.go:6549` | api-gateway | **BUILT** |
| TM-08 | Digest pinning in docker-compose.yml | ✅ RESOLVED (2026-05-27): All images in `package/adamance/docker-compose.yml` (single-host) are now digest-pinned. `freeipa/freeipa-server:rocky-9-4.12.2@sha256:e1113f67eff871768aa6d2d5929911b28f9e45fd94c8cbecd491daca01f9d40e`, `openpolicyagent/opa:latest@sha256:541f92bc1b3077453b51e3ffc7f529be188bfab56d3600c5907b3e2cb85fb33e`, `wazuh/wazuh-indexer:4.8.0@sha256:42a563f4c94bf498b87fec9b583448f8509d920dc3b39c83f8857142367ccf47`, `wazuh/wazuh-manager:4.8.0@sha256:366f142ebb28920c41bf77af1dcded832a21e9d4ed9a63741656b43639592ca2`, `wazuh/wazuh-dashboard:4.8.0@sha256:ef94e02d31262364d4ea8e1166dda1106959de602aa24d9077628b68287f6b68`. `release.yml` `digest-check` job enforces no non-digest images in CI. `scripts/pin-digests.sh` automates digest updates. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** 🔴 The row's entire evidence base is a path that no longer exists: `package/adamance/docker-compose.yml` is absent from the tree. Re-measured against the composes that DO ship: `deploy/docker-compose.ha.yml`, `deploy/docker-compose.siem.yml` and `deploy/docker-compose.keycloak.yml` carry zero non-digest literal `image:` lines. `deploy/setup/docker-compose.setup.yml:181,255,344,492` supply the two adamance images from required env vars whose default text demands a digest but which nothing enforces at compose level. The `digest-check` job at `.github/workflows/release.yml:15` cannot run (Actions disabled); `scripts/lint-image-digests.sh` plus a Makefile target is the local replacement. Evidence: `deploy/setup/docker-compose.setup.yml:181` · `deploy/setup/docker-compose.setup.yml:492` · `.github/workflows/release.yml:15` · `scripts/lint-image-digests.sh:8` Tracked as an open gap: both image-shipping routes are blocked. | deploy | **PARTIAL** |
| TM-09 | Air-gapped installer distribution path | Document the internal package repo as a V1.5 requirement. V1 acceptable with GitHub Releases. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The Direction cell IS the decision to defer: "Document the internal package repo as a V1.5 requirement. V1 acceptable with GitHub Releases." That is a recorded choice not to build the air-gapped path for V1. ⚠️ Caveat the row does not carry: the V1 fallback it leans on is itself unmet — no GitHub Release has ever been published, and the only release ever built is 86 commits behind. ⚠️ Corrected 2026-09-26 (external review): the "V1 acceptable with GitHub Releases" premise was superseded when the gateway began serving the agent binary itself (TMS-07's re-measure: the script fetches from the gateway, not from GitHub Releases), so the agent path needs no GitHub at install time. What remains for V1.5 is an internal package source for the control plane's own images and packages, and ACCEPTED holds only for that half. Status read **ACCEPTED** until 2026-09-26. | docs | **PARTIAL** |
| TM-10 | Host keytab scope in IPA API call | ✅ RESOLVED (M7.1 + M7.3): enrollment handler scopes `host_add` and `ipa-getkeytab` to a single host principal `host/<fqdn>@REALM`. (The multi-tenant/MSP extension is descoped, single-tenant V1; see TM-25.) ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Scoped to exactly one host principal, and MEASURED HERE rather than taken from an earlier measurement, whose two citations were both error-return paths that established neither half. `keytab_ldap.go:127` builds `principal := fmt.Sprintf("host/%s@%s", fqdn, realm)` and `:132` places that single principal in the LDAP extended request (`buildGetKeytabRequest(principal, enctypes)`). One host, one principal, per call. Evidence: `src/api-gateway/internal/ipa/keytab_ldap.go:127` · `src/api-gateway/internal/ipa/keytab_ldap.go:132` | api-gateway | **BUILT** |
| TM-11 | SSH CA signing key storage and key ceremony | ✅ RESOLVED: ceremony reviewed; as-built matches docs; checklist present; prod HSM is V1.5. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The ceremony documentation exists (the signing-ceremony runbook) and the row itself defers the production HSM to V1.5, so that clause is a recorded deferral rather than a gap. What is missing is everything downstream of the key: a production install starts no SSH certificate authority at all while its config points at one and calls the control active, and nothing in a shipped install makes any host validate an adamance SSH certificate — no config trusts the CA and nothing places the CA key. | security | **PARTIAL** |
| TM-12 | FIM monitoring of adamance agent log paths | ⚠ Corrected 2026-09-01: this row named `hostconfig/wazuh.go`, which has never existed. The agent's `ossec.conf` is written by `patchOssecConf` in `src/client-agent/internal/wazuh/register.go:219`, which overwrites the file with `<client>`, `<client_buffer>` and `<logging>` only (no `<syscheck>` stanza) and the fragment `writeWazuhConfig` writes (`src/client-agent/internal/enroll/enroll.go:422`) carries only a server address, port, protocol, hostname and enrollment key. So no adamance code emits a FIM watchlist: `policies/fim/policy.rego` would generate one but self-declares NOT WIRED with no runtime consumer, and `/var/log/adamance/` is not among `fim_monitored_paths` in `policies/data/global.json`. Read those two writers to confirm; any FIM of that path would have to come from manager-side config, which this repo does not carry (`deploy/dev/wazuh/config/ossec.conf` leaves syscheck to the image defaults). ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The row's own 2026-09-01 correction reproduces exactly. `patchOssecConf` is at `src/client-agent/internal/wazuh/register.go:219` and the file's only mention of syscheck is the comment at `:222` — "Keep FIM / syscheck from whatever config exists; just update the <client> section" — i.e. it writes none. `writeWazuhConfig` is at `src/client-agent/internal/enroll/enroll.go:422`. `policies/fim/policy.rego:9` still self-declares "STATUS (2026-07-08 audit): NOT WIRED. Nothing queries adamance.fim.policy — no consumer". And `/var/log/adamance/` is absent from `fim_monitored_paths` in `policies/data/global.json:28-44`, which lists `/var/lib/adamance/` and not the log path. No adamance code emits a FIM watchlist for the agent's own logs. Evidence: `src/client-agent/internal/wazuh/register.go:219` · `src/client-agent/internal/wazuh/register.go:222` · `src/client-agent/internal/enroll/enroll.go:422` · `policies/fim/policy.rego:9` | client-agent | **NOT_BUILT** |
| TM-13 | Sudo command audit via Wazuh syslog/auditd | Host OS-level configuration outside adamance agent scope. Document as a host hardening prerequisite. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The proposed direction is explicitly documentary — "Host OS-level configuration outside adamance agent scope. Document as a host hardening prerequisite." The deployment guide carries it: "`auditd` — must be running. The Wazuh agent reads audit logs." The body of this document restates the scope boundary. The tree has since gone further than the direction required (`src/client-agent/internal/hostconfig/auditd_rules.go` exists), which does not change the verdict. ⚠️ Corrected 2026-09-26 (external review): superseded by TMS-14's 2026-09-22 re-measure, which found that the agent now writes the sudo capture itself (the sudoers event-log drop-in, auditd rules and `pam_tty_audit`), so sudo audit is adamance's control and not a host prerequisite. Still owed: the capture applies on every governed host rather than only at enrolment with the opt-in seeded off, and a shipped detection rule fires on a sudo anomaly and pages. Status read **BUILT** until 2026-09-26. | docs | **PARTIAL** |
| TM-14 | Kerberos ticket lifetime enforcement | Verify SSSD config generated by `hostconfig/sssd.go` sets `krb5_lifetime` and per-principal `max_life`. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Half the verification the row asks for succeeds and half fails. `src/client-agent/internal/hostconfig/sssd.go:73-74` does set `krb5_lifetime = 8h` and `krb5_renewable_lifetime = 24h`, mirrored for the bastion at `src/client-agent/internal/hostconfig/bastion.go:93-94`. The per-principal `max_life` clause is unmet: a tree-wide grep for `max_life` across `src/**/*.go` returns only those two `krb5_lifetime` hits and nothing setting a FreeIPA per-principal `max_life`. Evidence: `src/client-agent/internal/hostconfig/sssd.go:73` · `src/client-agent/internal/hostconfig/sssd.go:74` · `src/client-agent/internal/hostconfig/bastion.go:93` | client-agent | **PARTIAL** |
| TM-15 | OPA policies default-deny review, IN PROGRESS | Partially done: core API authz, enrollment, SSH, sudo, lib/decision reviewed. Two bugs found and fixed (see below). CIS compliance policies not yet reviewed. Remaining: firewall, fim, data, governance packages. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** ⚠️ An earlier measurement misread a PAST TENSE as a current status. `policies/firewall/host.rego:14` says it was "NOT WIRED from the 2026-07-08 audit until then" — a historical note — and `:12` names what wired it: `internal/cli/daemon/groupingress.go`, on boot and on every bundle update. So "two of the four self-declare unwired" is false; only `policies/fim/policy.rego:9` does. Evidence: `policies/firewall/host.rego:12` · `policies/fim/policy.rego:9` | policies | **PARTIAL** |
| TM-16 | Bundle TTL for security-critical policies | ✅ RESOLVED: `bundle.critical.tar.gz` is now built by `release.yml` (Job: build-policies) and `policies-build.yml` (main branch). Served by `bundle.go` at `/policies/bundle.critical.tar.gz` with `CriticalMaxAge=60s` (≤60s per threat model). Critical bundle sources: `policies/firewall`, `policies/lib/decision.rego` (`policies/sudo` was REMOVED because sudo policy comes from FreeIPA; the build now FAILS if a listed critical source is missing). Signed with K-06 key. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The decision is the TTL, and the TTL is built and wired. `src/api-gateway/internal/bundle/bundle.go:75-80` declares `CriticalMaxAge` as the Cache-Control max-age "(≤60s per THREAT_MODEL.md §Bundle TTL)"; `:217-218` defaults it to `60 * time.Second`; `:226` sets the critical bundle path; `:244` passes it into the server. ⚠️ The row's "built by release.yml" clause cannot execute while Actions is disabled; the local `scripts/build-policies.sh` path is what actually produces the artefact today. ⇒ NONE for the TTL itself — the CI producer cannot run. Evidence: `src/api-gateway/internal/bundle/bundle.go:75` · `src/api-gateway/internal/bundle/bundle.go:217` · `src/api-gateway/internal/bundle/bundle.go:226` ⚠️ Corrected 2026-09-26 (external review), measured at `27679898d`: the TTL is served and nothing consumes it. No agent code requests the critical bundle (`grep -rniE critical src/client-agent/internal/bundle src/client-agent/internal/opa` over non-test files: no match; the same walk finds `pull.go`'s two bundle paths), and the bundle carries firewall and library policy, not the SSH or admin-group policy the vector row names. Status read **BUILT** until 2026-09-26. | api-gateway + policies | **PARTIAL** |
| TM-17 | CI policy build pipeline verification | ✅ RESOLVED: `build-policies` job in `release.yml` runs regal lint, `opa test`, `opa eval` fixture regression, `opa build --signature-key`. `policies-build.yml` CI also covers this. `make verify-policies-bundle` target exists. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The pipeline definition exists (`.github/workflows/release.yml` carries the jobs the row names) and a local `verify-policies-bundle` target is declared in the Makefile at `:12` with its self-test referenced at `:1264`. The verification clause is unmet in the only way that matters: GitHub Actions is disabled at the repository level, so the CI half has not run since 2026-08-02 — nothing verifies the policy build on a PR. Evidence: `Makefile:12` · `Makefile:1264` · `.github/workflows/release.yml:15` | CI | **PARTIAL** |
| TM-18 | Audit log sink verification for production | ✅ RESOLVED (2026-05-27): `WazuhEmitter` in `src/common/audit/wazuh.go` sends events to Wazuh indexer via OpenSearch bulk API (`/_bulk`) when `WAZUH_INDEXER_URL` is set; falls back to stdout when not configured so no audit events are silently dropped. Both dev stack (`deploy/dev/docker-compose.dev.yml`) and the single-host production package (`package/adamance/docker-compose.yml`) wire `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS` to api-gateway. Dev stack additionally passes `WAZUH_INDEXER_CA_CERT`. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The emitter is real and wired: `src/api-gateway/cmd/server/main.go:455` reads `WAZUH_INDEXER_URL` and `:468-470` the credentials and CA path. Two clauses of the row are now false or weak. (a) The cited production compose `package/adamance/docker-compose.yml` does not exist; the surviving wiring is `deploy/dev/docker-compose.dev.yml:551` and `deploy/setup/compose.d/35-siem.yml:5`. (b) Both set it as `${WAZUH_INDEXER_URL:-}` — empty by default — so an install without the SIEM profile falls back to stdout, which the row frames as a safety net rather than as the default it actually is. Evidence: `src/api-gateway/cmd/server/main.go:455` · `deploy/dev/docker-compose.dev.yml:551` · `deploy/setup/compose.d/35-siem.yml:5` ⚠️ Corrected 2026-09-26 (external review): "so no audit events are silently dropped" does not hold as a property. Stdout is not a sink anyone reads, so a production install without the SIEM profile keeps the audit copy nowhere but the chain. Stdout is a degraded state the compliance surface must report, not a fallback that satisfies this row. | deploy | **PARTIAL** |
| TM-19 | Second-approver enforcement for high-impact policy changes | ✅ RESOLVED (2026-06-11, `b7051bcc`): `policies/governance/require_approval.rego` (decision `governance.require_approval`) ⚠️ **Corrected 2026-09-02: this read "2 distinct non-self approvers" and that is wrong.** `policies/governance/require_approval.rego:42-48`: `second_approver: false`, the default, requires **one** distinct approver, which is two-person control counting the requester. `true` requires two approvers, which is three-person control. The requester is never counted toward the total either way., `policy.Handler` in `src/api-gateway/internal/handlers/policy/handler.go`, approval store in `src/api-gateway/internal/storage/approval/store.go`, route at `src/api-gateway/cmd/server/main.go:4819`. ⛔ **NOT graceful degradation, it fails CLOSED**: `src/api-gateway/internal/handlers/policy/handler.go:365` refuses the publish when the rule is not loaded. The legacy `governance.require_second_approver` never compiled and left this gate fail-OPEN; it was retired. Migration: `src/api-gateway/internal/db/migrations/0008_policy_change_approvals.sql` (renumbered from `002_policy_approvals` by the 2026-06-15 consolidation). ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Approver counting is documented and the evaluator fails closed: `require_approval.rego:42-48` defines `second_approver` false → 1 distinct approver, true → 2, with "The requester (input.actor) is NEVER counted"; `policy/handler.go:365` refuses when the rule is absent. ⚠️ One citation dropped as dead: `main.go:4819` is a blank line — the host-groups registration is at `:4817-4818`. Evidence: `policies/governance/require_approval.rego:42` · `src/api-gateway/internal/handlers/policy/handler.go:365` · `src/api-gateway/cmd/server/main.go:4817` | api-gateway | **BUILT** |
| TM-20 | single-host topology and the operator-pivot control | ✅ RESOLVED: single-host exemption documented in threat model. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The Direction was to DOCUMENT the operator↔control-plane pivot as N/A on single-host, and it is documented: `THREAT_MODEL.md:204` carries the withdrawn-2026-09-02 correction and the 2026-09-15 re-measurement, and `:152` records the gateway→Postgres boundary as "TLS (local socket in single-host)". ⚠️ Citation corrected: TM-20 is listed at `:86`, not `:87`. ⚠️ Corrected 2026-09-26 (external review): the exemption this row documents is withdrawn (see TMS-22), and the evidence above cited `THREAT_MODEL.md:204`, which is the LDAP/Kerberos exposure row, not the exemption. The requirement now applies to single-host deployments. Status read **BUILT** until 2026-09-26. | threat model | **NOT MEASURED** |
| TM-21 | TLS 1.3 enforcement in api-gateway Go server | ✅ RESOLVED: `src/common/mtls/tlsconfig.go` sets `MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13`. TLS 1.2 rejected. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** `src/common/mtls/tlsconfig.go` pins TLS 1.3 in both config builders: `:34-35` and `:47-48` each set `MinVersion: tls.VersionTLS13` and `MaxVersion: tls.VersionTLS13`, so TLS 1.2 is rejected on the server side by construction. The only remaining `VersionTLS12` reference in that package's neighbourhood is a version-to-string mapper at `src/api-gateway/internal/server/endpoints.go:161`, not a configuration. Evidence: `src/common/mtls/tlsconfig.go:34` · `src/common/mtls/tlsconfig.go:47` · `src/api-gateway/internal/server/endpoints.go:161` | api-gateway | **BUILT** |
| TM-22 | Argon2id for locally-managed password hashing | ✅ RESOLVED: No direct password storage in api-gateway. All auth delegates to FreeIPA. Compliant by design. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Compliant by design: no USER password storage in the gateway — authentication delegates to FreeIPA/Keycloak, so there is no local password hash to choose an algorithm for. ⛔ **The absence claim is narrower than it first looked, and a three-term grep (`bcrypt/scrypt/argon2`) got it wrong:** `src/api-gateway/internal/db/runtimerole.go:252` DOES run `pbkdf2.Key(sha256.New, …)`. That is SCRAM-SHA-256 credential derivation for the PostgreSQL runtime role (RFC 5802 §3, quoted at `:229`), not a password store — and the code already treats it as a guessing target, enforcing a 16-character entropy floor at `:176` because "a 4096-iteration PBKDF2 over a short password is a weak one". The row's requirement is unaffected; the earlier wording "no local password hashing to get wrong" was false as stated. Evidence: `src/api-gateway/internal/db/runtimerole.go:252` · `src/api-gateway/internal/db/runtimerole.go:229` · `src/api-gateway/internal/db/runtimerole.go:176` | api-gateway | **BUILT** |
| TM-23 | Internal service clients use TLS 1.2 instead of TLS 1.3 | ✅ RESOLVED (2026-05-27): the 8 api-gateway/wazuh-bridge clients → `MinVersion: tls.VersionTLS13`. **2026-07-11 re-verification caught a residual the "no VersionTLS12 in src/" claim missed: the client-agent join bootstrap (`enroll/join.go`, 3 paths) still allowed TLS 1.2 → fixed to `tls.VersionTLS13` (commit `574dfad`). Now genuinely zero `VersionTLS12` in `src/`.** ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** 🔴 The row's absolute claim is FALSE. It states "Now genuinely zero `VersionTLS12` in `src/`" — but `src/api-gateway/internal/notifier/notifier.go:153` calls `c.StartTLS(&tls.Config{ServerName: d.host, MinVersion: tls.VersionTLS12})` in non-test code inside `src/`. The eight internal service clients the decision is actually about do appear to be TLS 1.3 (`src/common/mtls/tlsconfig.go:34,47`), and the client-agent join bootstrap fix the row describes holds; the remaining non-test `VersionTLS12` occurrences elsewhere are a version-string mapper (`endpoints.go:161`) and test fixtures. The SMTP notifier is the one live residual. Evidence: `src/api-gateway/internal/notifier/notifier.go:153` · `src/common/mtls/tlsconfig.go:34` · `src/api-gateway/internal/server/endpoints.go:161` | api-gateway + wazuh-bridge + client-agent | **PARTIAL** |
| TM-24 | (reserved) | A reserved id with no decision recorded against it. It states no requirement, so there is nothing to build and nothing to rule on. ⚠️ Given a verdict only because the census scores every row in a table whose header names a Status column, and a blank cell there renders as an empty verdict. | — | **ACCEPTED** |
| TM-25 | Tenant isolation at the FreeIPA layer (NF-1) | ⛔ **N/A for V1, multi-tenancy was REMOVED.** adamance is single-tenant for V1 (never-MSP decision); the multi-tenant backend was deleted (`0248ebb`), so there is no per-tenant attack surface in V1. The `tenants` table is retained ONLY as the Sites FK-anchor to a single default tenant. The per-tenant Kerberos-principal isolation design is a **V2** concern and is NOT wired for V1. (Historical: it superseded the S-15 `{"TenantID": …}` option-key approach FreeIPA silently discarded.) ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** A recorded ruling, not an unbuilt control. The row itself marks it N/A for V1 because multi-tenancy was removed (commit `0248ebb`), and an open gap corroborates from the other side: multi-tenancy was deleted rather than switched off and serving several organisations means rebuilding the data partitioning, isolation rules and policy layer. Memory's standing ruling (V1 excludes multi-tenancy and federation; both are a paid business tier) agrees. | V2 (deferred) | **ACCEPTED** |
| TM-26 | Trusted time | ⭐ OPEN (2026-09-04). Every lifetime, expiry and freshness check in this document trusts a clock nobody authenticated. Direction: NTS or control-plane-restricted NTP, a bounded skew check at the gateway, and a decision that fails rather than ages gracefully when a host's clock is not trustworthy. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Not one clause of the direction exists. No NTS anywhere. Every FreeIPA install path in the tree deliberately disables time sync — `--no-ntp` appears in `deploy/terraform/aws/templates/ipa_user_data.sh:52` and the GCP/Azure equivalents, and `deploy/docker-compose.ha.yml:442` inherits the same flag set. The one place a skew check is even named is a stub: `deploy/freeipa/phases/A-preflight.sh:48` logs "[placeholder] time skew: system clock within 60s of NTP source". The gateway has no bounded-skew gate; the only skew handling in `src/` is per-field tolerance inside individual handlers (e.g. a 60s OIDC allowance at `src/api-gateway/internal/session/mintvalues.go:293`), which is the opposite of failing rather than ageing gracefully. Evidence: `deploy/freeipa/phases/A-preflight.sh:46` · `deploy/freeipa/phases/A-preflight.sh:48` · `deploy/terraform/aws/templates/ipa_user_data.sh:52` · `src/api-gateway/internal/session/mintvalues.go:293` | control plane + agent | **NOT_BUILT** |
| TM-27 | Revocation convergence | ⭐ OPEN (2026-09-04). No single statement of how long a revoked credential keeps working, per credential type, or what happens while its authority is unreachable. Direction: one table covering all twelve credential types, with a measured bound each. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The direction is one table covering all twelve credential types with a measured bound each, and no such table exists. A sibling row to the trusted-time gap states the same finding and supplies the measurement: the twelve revocable things each carry their own TTL configured in its own place, `git grep -ci 'convergence' origin/main -- THREAT_MODEL.md` returns 0, and the two poll loops both default to a literal `60` that means sixty seconds in one file and sixty minutes in the other. | control plane | **NOT_BUILT** |
| TM-28 | SSH revocation convergence is unmeasured | ⭐ OPEN (2026-09-04). The KRL path is built end to end — gateway builds it, agent fetches and SIGHUPs, sshd loads it via `RevokedKeys`. What is open is the bound: the agent's default poll interval is 60 minutes and nothing measures the real convergence on a managed host. The KRL is unsigned. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The row itself concedes the mechanism is built end to end and that what is open is the bound and the signature — neither of which exists. This is tracked as an open gap: "SSH revocation does reach `sshd`, and nothing measures how long it takes or signs what arrives." A sibling row's evidence pins the 60-minute default: `PollInterval = 60` in `src/client-agent/internal/crl/fetcher.go` multiplied by `time.Minute`. Nothing measures real convergence on a managed host and the KRL is unsigned. | api-gateway + agent | **NOT_BUILT** |
| TM-29 | Approval binding, replay and TOCTOU | ⭐ OPEN (2026-09-04). Approvals count approvers and do not bind to what was approved. Direction: bind to normalized operation, requester, target, content hash, policy revision, expiry and a single-use nonce, across policy publish, agent escalation, break-glass and restore. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Approval-matrix entries are canonicalised per field. ⚠️ Both citations corrected — each pointed at a doc comment while the claim was about wiring: the call is `resourceID := approvalMatrixResourceID(op, entry)` at `approvalmatrix/handler.go:331` and the function itself is below `:379`, not at the comment lines first cited. Evidence: `src/api-gateway/internal/handlers/approvalmatrix/handler.go:331` | policies + api-gateway | **PARTIAL** |
| TM-30 | Audit completeness and mutation atomicity | ⭐ OPEN (2026-09-04). The chain proves nothing was altered; nothing proves everything was written. Direction: intent before mutation, outcome after, an explicit unconfirmed state, reconciliation, and a failed append that fails the operation. ⚠️ **Re-sequenced 2026-09-05. The requirement is unchanged and still owed; the ORDER in it was doing work it cannot do.** "A failed append fails the operation" is only implementable while the operation can still be refused. An append attempted after the response has been written cannot retroactively fail anything, and an append that times out has not said whether it committed — so the sentence as written describes a control that is impossible in the tail case it most needs to cover. Ordered properly: the **intent** record commits *before* the mutation is attempted and the operation is refused if that write fails; the **outcome** record follows; where the outcome cannot be confirmed the operation is stored as explicitly unconfirmed rather than as either success or failure; and reconciliation resolves those. ⚖️ **An external reviewer read this row as a withdrawn claim that the control is built. It is not — it is a requirement, and the reading rule at the top of this document says so.** Recorded here because misreading a contract row as a status row is the single most likely way for a reader to get this document wrong. See TMA2-14 for the concurrency half. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** None of the four re-sequenced clauses exists — intent-before-mutation, outcome-after, an explicit unconfirmed state, or reconciliation. A grep of `src/common/audit/*.go` (non-test) for `intent`, `unconfirmed` and `reconcil` returns only unrelated `//nolint` boilerplate about not mutating an emitted event. This is tracked as an open gap: "A privileged change can land while the audit entry recording it does not, and nothing reconciles the difference." The row's own ⚖️ note is correct that this is a requirement and not a status claim. | api-gateway + audit | **NOT_BUILT** |
| TM-31 | Anchor signing key is the audit chain key | 🔴 OPEN (2026-09-04), raised as a question and measured against the tree the same day. The anchor is signed with the chain's own symmetric key, so verifying an anchor and forging one are one capability. ⚖️ **OPERATOR REFUTED, 2026-09-05. This row continued "and the off-box witness does not witness A4", and it read as an absolute. It is not one.** An anchor that had already reached a destination the control plane cannot rewrite is beyond somebody who takes the key afterwards: holding the key buys a *conflicting* history, not the erasure of the one already sent. The witness is defeated going forward, not retroactively. See TMA2-06. ⚠️ **Corrected 2026-09-05: this row also read "Highest priority of the items added on this date."** That ranking did not survive the day. TM-41 establishes that separating the signing key buys nothing while A4 can bypass the chain entirely, so the 09-04 priority was wrong when it was made. Direction is unchanged and still owed: an asymmetric signing key that is not the chain key, a public half distributed off the audited box, and a stated rotation and compromise recovery — with the standing caveat that a private half living on the control plane does not escape A4 whatever algorithm signs with it. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The direction asks for an asymmetric signing key that is not the chain key, a public half distributed off-box, and a stated rotation/compromise story. None exists: a grep for `ed25519` and `asymmetric` across `src/common/audit/*.go` and `src/api-gateway/internal/storage/auditchain/*.go` (non-test) returns zero hits. The anchor row still stores only `(anchor_seq, head_hash, key_id, sink)` — `src/api-gateway/internal/storage/auditchain/store.go:101` — with no separate signature column. The defect is owned, the build item is ruled (DIRECTED 2026-09-05: BUILD IT), and the hardware position is still unruled. Evidence: `src/api-gateway/internal/storage/auditchain/store.go:101` | audit anchoring | **NOT_BUILT** |
| TM-32 | Off-box preservation, not just off-box witness | ⭐ OPEN (2026-09-04). Only the chain head leaves the box, so destruction of the local store is provable and not recoverable. ⚠️ **Corrected 2026-09-05: this row read "decide whether the full event stream ships to immutable storage", and by then it had been decided.** TMA2-06 ruled that the events themselves ship, not just the head. What the second pass withdrew was the *ranking* that came with the ruling, never the ruling. Direction: ship the event stream, state the confidentiality consequence in the same breath because entries carry principals, hostnames and actions, and do not let it ride the anchor tick — TMA2-10 measures a five-minute window, and events shipped on that timer inherit it. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** An open gap measures it directly: `WriteAnchor`'s parameters are `(seq, headHash, keyID, sink)` and no entry payload is among them — confirmed against the SQL at `src/api-gateway/internal/storage/auditchain/store.go:101`, which inserts into `audit_chain_anchors (anchor_seq, head_hash, key_id, sink)` and nothing else. Only the head leaves the box; the event stream does not. TMA2-06's ruling that the events themselves ship is recorded, and nothing has been built against it. Evidence: `src/api-gateway/internal/storage/auditchain/store.go:101` ⚠️ Clarified 2026-09-26 (external review): "only the head leaves the box" is true of the anchor path and not of the event stream as a whole. TMA2-06 records that `WazuhEmitter.Emit` sends every audit event to the Wazuh indexer. What is missing is preservation in a destination the control plane cannot rewrite; a mutable indexer copy does not satisfy this row. | audit anchoring | **NOT_BUILT** |
| TM-33 | Console web surface | ⭐ OPEN (2026-09-04). OIDC flow parameters, rendering of attacker-supplied strings, and object-level authorization were never modelled. Direction: PKCE/state/nonce/exact redirect, CSP with no inline script, per-object authorization and field allowlists on write. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** 🚨 **An earlier measurement's central claim was FALSE and is retracted here.** It said the only CSP in the tree is `deploy/dev/caddy/Caddyfile:39` and that "a production console ships with no CSP at all". There are THREE: `configs/caddy/Caddyfile.setup:58` and `configs/caddy/Caddyfile.ha:107` carry an identical policy (`default-src 'self'; script-src 'self'; … frame-ancestors 'none'`), and **Caddyfile.setup IS mounted into the production edge proxy** — `deploy/setup/docker-compose.setup.yml:647`. Production does ship a CSP. Verified independently before landing. Evidence: `configs/caddy/Caddyfile.setup:58` · `configs/caddy/Caddyfile.ha:107` · `deploy/setup/docker-compose.setup.yml:647` | admin-ui + api-gateway | **PARTIAL** |
| TM-34 | Enrollment lifecycle beyond first join | ⭐ OPEN (2026-09-04). CA bootstrap trust, token entropy and handling, SAN rather than CN, proof of possession, host cloning, re-enrollment and decommission. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Four of the seven named concerns are built. Proof of possession: `src/api-gateway/cmd/server/main.go:1219` calls `machines.CSRBoundToHost(csrPEM, jr.Hostname)` before `host_add`, with the reasoning at `:1214-1218`. Re-enrolment: refused explicitly at `src/api-gateway/internal/enrollment/handler.go:695-713` ("host %q is already enrolled; rotate its credential instead of re-enrolling"), with the store-side rule at `store.go:321,350`. Decommission: gated and audited at `policies/api/authz.rego:1014-1021`, and enforced at use by the host-lifecycle gate. Unmet: SAN-rather-than-CN — `src/api-gateway/internal/middleware/hostcert.go:40-45` still falls back to the Subject CN when no DNS SAN is present; CA bootstrap trust on a stock install is broken. ⚠️ Token entropy and host cloning NOT measured. Evidence: `src/api-gateway/cmd/server/main.go:1219` · `src/api-gateway/internal/enrollment/handler.go:695` · `src/api-gateway/internal/enrollment/handler.go:713` · `policies/api/authz.rego:1014` | api-gateway + client-agent | **PARTIAL** |
| TM-35 | Availability and fail direction | ⭐ OPEN (2026-09-04). Resource exhaustion is the least-covered category here, and no component states whether losing a dependency fails open or closed. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** An open gap measures it precisely: individual code paths HAVE decided and documented their direction — `src/api-gateway/cmd/server/decision_check.go:252` records the segmentation overlay as fail-OPEN by design and `:315` records the SSH CA path as fail-closed — but no document states, per dependency, which way the product goes when OPA, FreeIPA, Postgres or Keycloak is unreachable. Its own evidence: `git grep -c 'fails open\/fails closed' origin/main -- THREAT_MODEL.md` returns 0. Resource exhaustion remains the least-covered category with no control at all. | all | **NOT_BUILT** |
| TM-36 | Secrets store as a trust boundary | ⭐ OPEN (2026-09-04). OpenBao appears in the README and in no threat model. Unseal shares, root and recovery tokens, bootstrap, backup and total-loss recovery. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The row's own ⚠️ correction is right, and a re-measurement on 2026-09-18 found `git grep -ci 'openbao' -- THREAT_MODEL.md` now returns 5, not the 0 the open gap recorded — OpenBao is at asset row 11 of this file, `:157`, `:248`, `:321` and `:1093`, and the unseal-share contract is stated. So the inventory half landed. What is still owed is what the row says is owed: no *subsystem* threat model covers the unseal ceremony, share custody, root/recovery-token handling, bootstrap, backup or total-loss recovery, and an open gap records that whether auto-unseal is permitted at all has never been ruled. A re-measurement adds that a TPM-equipped install still leaves the unseal keys in plaintext. | deploy + api-gateway ⚠️ **Corrected 2026-09-05: "and in no threat model" is false of the document containing the sentence.** The same 2026-09-04 pass that wrote this row added OpenBao to the asset table, to the trust boundaries and to the cross-cutting section of this file. What is still true is the reason the row was written: no *subsystem* model covers the unseal ceremony, share custody or recovery-token handling, and the rows added here are an inventory entry rather than a model. | **PARTIAL** |
| TM-37 | Restore as a security event | ⭐ OPEN (2026-09-04). Backup tampering is modelled; restoring is not. A restore can resurrect a revoked credential or a deleted account. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** There is no restore operation in the policy vocabulary: `grep -n 'restore' policies/api/authz.rego` returns exactly ONE hit and it is a comment (`:2397`). Restore drills exist only as Makefile targets (`drill-restore`, `drill-backup`). ⚠️ The row previously said that comment "mounts DR history as read-only" — a comment mounts nothing; the rule it describes sits below it. Evidence: `policies/api/authz.rego:2397` · `Makefile:69` · `Makefile:257` | deploy + control plane | **NOT_BUILT** |
| TM-38 | Identity canonicalization | ⭐ OPEN (2026-09-04). No single canonical principal form across Keycloak, FreeIPA, Samba and SSH. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** An open gap measures the absence with a positive control: `git grep -l 'CanonicalPrincipal' -- src/ / wc -l` returns 0, while the hostname equivalent exists at `src/api-gateway/internal/hostname/hostname.go`. My own broader grep for `canonicaliz/CanonicalPrincipal` across `src/` non-test finds only host-shaped canonicalisation — `src/api-gateway/internal/sshca/client.go:379` (`CanonicalHost`, the ADR-0005 rule), an FQDN case note at `reconciler.go:213`, and approval-entry canonicalisation at `approvalmatrix/handler.go:329`. Hostnames got the treatment; principals did not. Four systems each hold their own spelling. Evidence: `src/api-gateway/internal/sshca/client.go:379` | control plane | **NOT_BUILT** |
| TM-39 | Recording and audit privacy | ⭐ OPEN (2026-09-04). A 90-day ISM retention policy is installed at startup and the gateway continues when it cannot be. Encryption at rest, an export operation to audit at all, and redaction are absent. See TMSR-03 and TMSR-04. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** One of four clauses is half-built and three are absent. Retention: a 90-day ISM policy IS installed against the session indices at startup, but `src/api-gateway/cmd/server/main.go:2606` logs that without an admin indexer credential the "session indices will grow unbounded until it is installed out-of-band" and the gateway continues — so whether recordings are ever deleted rests on a credential nothing checks. Export: `git grep -c 'recordings.export' -- policies/api/authz.rego` returns no match, against `recordings.read → 4`, so there is no export operation to audit at all. Redaction: not built. Encryption at rest: operator attestation only, an operator's word rather than something the product measures. Evidence: `src/api-gateway/cmd/server/main.go:2606` | api-gateway + storage | **PARTIAL** |
| TM-40 | Revocation is not checked on certificate-authenticated routes | 🔴 OPEN (2026-09-04), measured. Four routes authenticate the certificate and never ask whether the host is still enrolled; one of them serves every RADIUS shared secret. Revoking a host currently changes the console and not the API. Direction: enrollment status checked at every use, inside the TM-27 bound. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** 🔴 AN OPEN GAP REVERSES THIS ROW — the main clause is BUILT and the row still says OPEN. `src/api-gateway/internal/middleware/hostlifecycle.go:19-45` is a dedicated admission gate whose stated job is "refuse EVERYTHING once a host is decommissioned", covering all fifteen host-mTLS operations by name including `radius.clients_config.read` (the every-RADIUS-shared-secret route the row cites) and `machine.renew_cert`. It is wired at `src/api-gateway/cmd/server/main.go:4047` on every `/api/v1` route, deliberately after `HostCertAuthn` (`:4032`) and before authz. It fails CLOSED three ways (`:70-80`): not-enrolled → 403, host-registry error → 503, unconfigured host registry → 503, with a true-nil interface guard at `:3636-3642`. Decommission invalidates the cache immediately (`:3646`). What is still owed is the row's second clause — "inside the TM-27 bound" — because TM-27's table does not exist, and the 30s cache lag reaches only one replica. Evidence: `src/api-gateway/internal/middleware/hostlifecycle.go:19` · `src/api-gateway/internal/middleware/hostlifecycle.go:70` · `src/api-gateway/cmd/server/main.go:4047` · `src/api-gateway/cmd/server/main.go:3640` | api-gateway | **PARTIAL** |
| TM-41 | The chain records what goes through the gateway, and A4 does not have to | 🔴 **OPEN (2026-09-05), measured, and the first thing to fix.** A4 is defined here as an insider who holds the database. They do not need to rewrite anything: they write to Postgres, or modify the directory over LDAP, or call the Keycloak admin API, and no chain entry is ever emitted. Nothing is altered, no anchor disagrees, and the chain stays complete, intact and anchored while being silently incomplete. **Measured, both halves:** the chain is application-level only — the sole triggers on the audit tables are defensive (`trg_audit_events_no_mutate`, `trg_audit_events_no_truncate`), and no trigger anywhere emits an entry when a governed table changes, so the only writer is `ChainEmitter` on the gateway request path; and the bypass is reachable, because `deploy/docker-compose.ha.yml` publishes `390:389`, `637:636`, `89:88/udp` and `465:464/udp` in short form, which binds them on every interface. ⇒ A perfect signer, a perfect write-once destination and a zero-second anchor interval all preserve nothing if the mutation never enters the chain. Direction: contain first by removing the all-interface exposure and cutting administrative reach from outside the control plane; then make the gateway the only permitted mutation path, or collect the native audit evidence of Postgres, FreeIPA and Keycloak independently and reconcile it against the chain. ⛔ Database triggers alone do not close this — a superuser is above them. **⚠️ SHARPENED 2026-09-13, measured on a running deployment: the gateway IS that superuser.** `adamance_app` — the POSTGRES_USER every shipped compose sets (`deploy/setup/docker-compose.setup.yml`, `deploy/docker-compose.ha.yml`), which the postgres image creates as `Superuser, Create role, Create DB, Replication, Bypass RLS`, and which the gateway's own DSN connects as — **owns `audit_events`**, so `ALTER TABLE audit_events DISABLE TRIGGER ALL` is available to it and both defensive triggers come off. ⇒ A4 above is described as "an insider who holds the database"; the bar is lower than that sentence implies — **anyone who obtains the gateway's database password already holds it**, and that credential sits in the gateway's environment. The audit-immutability design already names the mitigation ("keeping superuser creds offline and out of the gateway") and the deployment did the opposite. ⭐ First step landed: migrations moved out of the gateway's boot path, which is what forced its runtime role to hold DDL; provisioning a least-privilege runtime role that does not own the audit table is the follow-on, and until it lands this row's exposure is unchanged. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The containment finding stands, but ⛔ **its positive control was false and is withdrawn.** An earlier measurement claimed `grep -cE '390:389/637:636/89:88/465:464' deploy/docker-compose.ha.yml` returned 0 against 11 hits on the dev compose. Re-run: BOTH return 0 — the dev compose publishes `9000:9000`, `636:636`, `8444:443`, `8443:8443`, `8088:8080`, none matching that pattern. A grep that matches nothing anywhere is not evidence that anything was removed. The finding survives on the direct evidence instead: `deploy/docker-compose.ha.yml:376` and the port bindings actually present. Evidence: `deploy/docker-compose.ha.yml:376` ⚠️ Corrected 2026-09-26 (external review): the Direction above still opens with containing an all-interface port exposure, and that exposure no longer exists. The HA overlay was rewritten on 2026-09-05; measured again at `27679898d`, its only publication is the loopback-bound load balancer at `deploy/docker-compose.ha.yml:376`, and both replicas carry `ports: !reset []` (`:123`, `:144`). The 2026-09-21 re-measure cited `:376` as evidence of exposure; it is the loopback bind. The bypass stays reachable through the database role: `adamance_app` is a superuser that owns `audit_events` (sharpened 2026-09-13). Direction, restated: (1) a least-privilege runtime role that owns no audit table and cannot disable triggers, with the superuser credential kept off the gateway; (2) make the gateway the only permitted mutation path, or collect the native audit evidence of Postgres, FreeIPA and Keycloak independently and reconcile it against the chain. | control plane | **PARTIAL** |
| TM-42 | A signed, preserved, complete record can still name the wrong person | ⭐ OPEN (2026-09-05). The gap four separate reviews walked past. Even once TM-41 is closed and the stream is preserved off-box under a key A4 cannot forge, the `actor` on an event is a field the producer fills in — so a compromised gateway proves that the audit system asserted "Alice did X", never that Alice authorised X. An authenticated lie is still a lie, and this is the reason a signer alone does not settle attribution. Direction: bind each record to authentication material a verifier can check without trusting the producer — the session or token identity and its audience, the authorisation decision that permitted the operation, a digest of the request, and the resulting state transition — so the claim and the evidence for it travel together. ⚠️ **Corrected 2026-09-05: that direction fails its own test and all four reviewers said so independently.** Every item in it is produced, selected or mediated by the gateway, so under A4b the gateway attaches a real bearer identity to an invented request, manufactures the digest, reports an authorisation decision it solicited from itself, and describes a state it caused directly. Those four fields are better *evidence decomposition*; none of them is proof of intent, and shipping them first would add ceremony without assurance. What the record needs is **distinct fields carrying distinct assurance levels**, so a reader can see which claim rests on what: `authenticated_subject` (what the identity provider asserted), `requested_by` (who cryptographically authorised *this* request, if anyone), `authorized_by` (policy decision id, input hash, bundle hash), `executed_by` (the service identity that performed the mutation), and `observed_effect` (native-system evidence or an independently observed state transition). ⛔ Only two of those carry real weight against A4b, and both are unbuilt: a **client-origin proof** over the canonical operation — transaction-bound WebAuthn or request signing, ideally with an independent confirmation display — for high-risk mutations, and an `observed_effect` collected independently, which inherits TM-41's problem entirely. ⇒ Until the client-origin proof exists, the honest claim for ordinary operations is **authenticated-session attribution, not non-repudiation**, and this document should say that rather than implying the stronger one. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The row's own corrected direction names five distinct-assurance fields and then states that only two carry weight against A4b — a client-origin proof (transaction-bound WebAuthn or request signing) and an independently collected `observed_effect` — and that both are unbuilt. That holds: no WebAuthn transaction binding exists (the realm cannot even enrol a security key), and `observed_effect` inherits TM-41's unbuilt native-audit collection. It is tracked as an open gap with the matching headline: "A signed and preserved record still names whoever the compromised machine says it names." The row's closing instruction — that the document should say authenticated-session attribution rather than non-repudiation — is itself a documentation change that has not been made. ⚠️ Corrected 2026-09-26 (external review): the sentence above that "this document should say authenticated-session attribution rather than non-repudiation" asks this contract to narrow a requirement because the code is behind, which the reading rule at the top forbids; the same row names the control that achieves non-repudiation. Restated, and unchanged as a requirement: a record of a high-risk mutation is attributable to its author by a proof the gateway cannot manufacture, a client-origin proof over the canonical operation plus an independently observed effect. What holds today is authenticated-session attribution only, and until the requirement is met no report may call an audit record non-repudiable. | control plane + policy | **NOT_BUILT** |
| TM-43 | Any authenticated user can ask for a JIT super_admin grant | ⚖️ **OPERATOR REFUTED, 2026-09-27.** Raised by the 2026-09-27 live verification run: an account in `admins` but not in `super-admins` asked for a `super_admin` grant, a standing super-admin approved it, and the account then acted as super_admin. The request door checks fresh MFA and the role name (`src/api-gateway/internal/handlers/jit/handlers.go:675-679`), never the requester's standing membership, and its gate carries no role predicate (`policies/api/authz.rego:1951`). The maintainer ruled that this is intended. Some deployments will need an ordinary user or an ordinary admin to ask for elevation, so who may **ask** stays open. ⚖️ **Why the maintainer refuted it, added the same day:** somewhere, someone's setup will need a regular user or a regular admin to be the one who requests elevation, and a rule that only a standing super-admin may ask would leave that setup with no way to ask at all. Asking confers nothing on its own. The decision that carries the risk is the approval, and that stays with a standing super-admin who is not the requester. So the result the live run recorded, an `admins` account that ended up acting as super_admin, is that control doing its job: a person who already held super_admin power chose to lend it, and both the request and the approval are on the record. The control is who may **approve**: standing `super-admins` membership only (`isSuperAdmin`, `src/api-gateway/internal/handlers/jit/handlers.go:1428`), and never the requester (`:935`) except in a deployment with a single standing super-admin (the single-super-admin exception in the JIT approver design). The residual risk is a careless approver; the request and the decision are both audited (`iam.jit.grant_requested`, `iam.jit.grant_approved`, `iam.jit.grant_denied`). ⚠️ This refutes one sentence in the JIT approver design, which says elevation requires "two distinct compromised principals, both standing members of `super-admins`". Under this ruling only the approver must be a standing member. | api-gateway (JIT) | **ACCEPTED** |
