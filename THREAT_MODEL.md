# Threat Model: adamance

> Status: **REVIEWED, and current as of the date below.** Owner: project maintainer.
> Last reviewed: **2026-09-04.** Prior passes: 2026-09-02, 2026-09-01, 2026-08-31, 2026-07-11, 2026-05-26, 2026-05-24.
>
> Seven subsystems have their own threat models and are not repeated here:
> [agent accounts](THREAT_MODEL_agent_accounts.md), [the installer](THREAT_MODEL_installer.md),
> [audit anchoring](THREAT_MODEL_audit_anchoring.md), [session recording](THREAT_MODEL_session_recording.md),
> [the Samba AD DC module](THREAT_MODEL_samba_ad_dc.md), [VPN, RADIUS and DNS](THREAT_MODEL_network_modules.md),
> and [Active Directory integration](THREAT_MODEL_ad_integration.md).

---

## How to read this document

**This document is the contract, not a status report.** A row states a threat and the control the code
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
| 5    | OPA bundle signing key                               | Push arbitrary policy to every managed host (e.g. allow any SSH)                      |
| 6    | API gateway JWT signing key                          | Forge admin sessions without touching the directory                                   |
| 7    | Postgres transactional store (MFA evidence, refresh tokens, enrollment tokens; DATA-02) | Forge fresh-MFA state to bypass every step-up gate, exfiltrate refresh/enrollment token hashes, replay enrollment |
| 8    | Wazuh agent enrollment key                           | Log spoofing, alert suppression, blind the SIEM                                       |
| 9    | Operator MFA recovery codes                          | Bypass MFA on operator accounts                                                       |
| 11   | OpenBao unseal shares and root/recovery token        | ⭐ Added 2026-09-04. Unseals the store holding several of the rows above, so it inherits their blast radius. Split across people, never on the store's own host, never inside the deployment's own backup. |
| 12   | Anchor signing key                                   | ⭐ Added 2026-09-04. Forge an off-box anchor and the only witness to a rewritten chain agrees with the rewrite. See [`THREAT_MODEL_audit_anchoring.md`](THREAT_MODEL_audit_anchoring.md). |
| 13   | Stored session recordings                            | ⭐ Added 2026-09-04. Everything anyone typed in a privileged session, in bulk. Ranked here and not only in the subsystem document because the disclosure needs no other asset first. |
| 10   | Audit logs                                           | Destruction or tampering hides any of the above                                       |

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

## Attack vectors and required controls

Each row is a documented threat plus the control(s) that address it. The control column drives implementation
requirements; if it's not built, the threat is open.

### Initial access (primarily A1)

| Vector                                        | Required control                                                                                                                                                                  |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Exposed admin UI / API on the public internet | V1 is private/VPN-only (SCOPE-10, Locked); bind to the private network / VPN (e.g. WireGuard, Tailscale); no public internet exposure. The public-exposure path (reverse proxy with WAF, IP allowlist) is **V1.5+** forward-looking design, not a V1 path. |
| Credential stuffing against admin UI          | MFA required for **all** admin accounts (FreeIPA OTP or WebAuthn). Rate limit on `/oauth/token`. Account lockout after N failed attempts with exponential backoff.                |
| Phishing of admin session cookie              | Short JWT lifetime (≤15m), refresh tokens bound to IP and User-Agent, MFA step-up required for sensitive operations (user creation, policy change, machine enrollment).           |
| Vulnerable upstream container image           | Pin all images by digest, not tag. Weekly Trivy scan in CI with a blocking severity threshold. Documented monthly patch cadence with emergency channel for CVEs ≥ 9.0.            |
| The browser-facing OIDC flow is attacked instead of the password | ⭐ Added 2026-09-04. `state` and PKCE on every authorization request, `nonce` validated on the ID token, exact-match redirect URIs with no wildcard or prefix match, an authorization code that can be exchanged once, and a session identifier rotated on every privilege change. **Status: NOT MODELLED.** The rows above cover the credential and the cookie; the flow that mints the cookie was never written down. |
| Content the console renders is attacker-supplied | ⭐ Added 2026-09-04. Hostnames, group names, approval reasons, audit fields, policy names and replayed transcript output all reach the console and all originate outside it. Output encoding at render, a CSP that forbids inline script, no CORS origin beyond the console's own. **Status: NOT MODELLED.** A stored script in a hostname runs with an operator's session and needs no phishing to get there. |
| An authenticated caller changes an identifier and reaches another subject's object | ⭐ Added 2026-09-04. Object-level authorization on every route that takes an identifier, decided against the object rather than the route, and request bodies bound to an explicit field allowlist so a client cannot set a field the handler never meant to accept. **Status: NOT MODELLED.** |
| Direct exposure of LDAP/Kerberos ports        | Only the reverse proxy is in the edge zone. ⚠️ **Corrected 2026-09-02: this row read "LDAPS/Kerberos are not reachable from outside the control plane subnet" and the shipped HA compose contradicts it.** `deploy/docker-compose.ha.yml:68-74` publishes seven directory and Kerberos ports in short form, so Docker binds them on all interfaces. The single-host package is unaffected. Tracked as an open gap; either the compose binds privately or this row stops claiming a containment it does not have. |

### Enrollment (primarily A1, A2)

| Vector                               | Required control                                                                                                                                                                                                 |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unauthorized host joining the domain | Enrollment requires a **one-time scoped token** issued by an authenticated admin, bound to an expected hostname, expiring within 24 hours. No anonymous enrollment. No `1515/authd` exposed without prior token. |
| MITM of the install script           | Install artifact is served over TLS only, from a pinned hostname, with a published SHA-256 checksum. Production deployments distribute via an internal package repository, not `curl \| bash`.                   |
| Replay of an enrollment token        | Tokens are single-use and consumed atomically by the API. Token use is logged with the source IP and resulting host principal.                                                                                   |
| Hostname spoofing during enrollment  | The enrolling host must present a CSR for the hostname declared in the token. The CA refuses to sign for a name not in the token. ⭐ Extended 2026-09-04: the match is against the SAN and not the CN alone, an extra SAN entry in the CSR is a refusal rather than an ignore, and the requester proves possession of the private key. **Status: PARTIAL**, the name check is built, the SAN and possession clauses are asserted nowhere. |
| The enrolling host trusts whichever CA answers first | ⭐ Added 2026-09-04. First contact is the weakest moment in the lifecycle and it is the moment the trust root gets decided. The agent pins the CA by a fingerprint delivered out of band with the token rather than trusting the first certificate it is shown, and the gateway refuses to complete an `--insecure` bootstrap for a production token. **Status: PARTIAL**, all three bootstrap modes exist in `src/client-agent/internal/enroll/join.go` and nothing refuses the weak one. |
| An enrollment token is guessed, or read out of a log or a shell history | ⭐ Added 2026-09-04. At least 128 bits from a CSPRNG, stored hashed, never logged in full, and delivered by a channel that is not the one carrying the install command wherever that is possible. A `curl \| bash` line with its own token in it lands the credential in two shell histories and a proxy log. **Status: PARTIAL**, single-use and expiry are built, entropy and handling are unstated. |
| A host is cloned, or re-enrolls under a name that already exists | ⭐ Added 2026-09-04. Enrollment for a name that is already active is refused rather than joined, unless the prior host was explicitly decommissioned. A VM image captured after enrollment carries a host key and a certificate, so two machines hold one identity and no audit trail can separate them. Decommission and rekey are lifecycle steps, not a manual tidy-up. **Status: NOT MODELLED.** |
| A decommissioned host keeps working | ⭐ Added 2026-09-04. Decommission revokes the host certificate, disables the host principal, invalidates the keytab and drops the host from bundle scope, inside the bound stated in the revocation-convergence row below. **Status: NOT MODELLED.** |

### Lateral movement (primarily A2)

| Vector                                                           | Required control                                                                                                                                                                        |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Compromised host uses its keytab to authenticate as another host | Host keytabs grant only the host's own identity. No transitive trust. User SSH uses **ephemeral certificates** issued by the internal SSH CA (step-ca, ARCH-05); host credentials are not accepted for user-initiated SSH. |
| Theft or misuse of the SSH CA signing key (issue rogue user certs) | SSH CA (step-ca, K-05) is a separate trust chain from Dogtag (CRYPTO-07); signing key home is Vault Transit / sealed offline file. Certs are short-lived; revocation, CRL distribution and CA-key-compromise threats are enumerated in the SSH CA design rather than here. |
| Compromised host modifies its own audit logs to hide activity    | ⚠️ **Corrected 2026-09-02: this row credited Wazuh FIM, which is not wired.** No adamance code emits a FIM watchlist (TM-12 below), and Wazuh is an optional module nothing gates on. The control that does hold is central: privileged actions land in the HMAC-SHA256 chain on the control plane, not on the host, and a signed anchor of the chain head leaves the box on a timer. See [`THREAT_MODEL_audit_anchoring.md`](THREAT_MODEL_audit_anchoring.md). Where an operator has installed the Wazuh agent, real-time forwarding is a second copy and not the primary control. |
| Compromised host pulls sensitive policies it shouldn't see       | 🔴 **NOT MITIGATED, corrected 2026-08-31.** Bundle requests are authenticated with the host certificate, and that is ALL that is checked. Bundles are **not** scoped per host group: every enrolled host receives byte-identical bundles. See the as-built note below. |
| Compromised host abuses its sudo rights to escalate              | sudo rules are scoped narrowly (specific commands, not `ALL=(ALL)`). Sudo invocations are audit-logged centrally and trigger alerts on anomaly.                                         |
| An SSH certificate is revoked and `sshd` never hears about it | ⭐ Added 2026-09-04. `sshd` consumes a KRL or `RevokedKeys`, not an X.509 CRL, so the revocation path has to produce, distribute and load the artifact `sshd` actually reads, with a measured convergence bound. The CRL endpoint at `src/api-gateway/internal/handlers/sshca/crl.go` is not on its own evidence that this holds. Short certificate lifetimes bound the damage and are not revocation. **Status: OPEN, unverified.** |
| A privileged mutation lands and its audit entry does not | ⭐ Added 2026-09-04. A valid hash chain proves what was written was not altered. It says nothing about what was never written, and a missing entry reads exactly like an action that never happened. FreeIPA, Keycloak, Postgres and OPA cannot share one transaction, so: intent recorded before the mutation is attempted, outcome recorded after, an outcome nobody could confirm stored as an explicit unconfirmed state rather than dropped, reconciliation to resolve those states, and an audit append that fails takes the operation down with it. **Status: NOT MODELLED.** |
| Stolen user TGT used from another host                           | Tickets are bound to addresses where possible. Short ticket lifetime (8h default per SSSD `krb5_lifetime`; 1h target for admin principals, enforced via per-principal KDC policy `max_life`). Renewal requires re-auth past max renewable lifetime (24h). |

### Policy bypass (primarily A3)

| Vector                                                            | Required control                                                                                                                                                                              |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| User exploits a gap in a policy that wasn't `default deny`        | All OPA decision documents and all FreeIPA HBAC rules are default-deny. Explicit allows only. Verified by policy unit tests in CI.                                                            |
| User races between policy update and enforcement                  | Local OPA decisions on the host. Bundle TTL ≤ 60s for security-critical policies. Push-on-change via webhook for the highest-impact policies (SSH, sudo, admin group membership).             |
| Policy change introduces a vulnerability that ships before review | Policy changes go through git → CI (rego unit tests, opa eval against fixtures) → review (one approver minimum; two for policies touching admin groups or root access) → signed bundle build. |

### Control plane compromise (primarily A4)

| Vector                                                | Required control                                                                                                                                                                                   |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Operator with API access silently escalates a user    | All write operations to FreeIPA and OPA are logged to Wazuh tagged with the operator's identity. Logs are write-only from the operator's perspective (separate retention bucket with object lock). |
| Compromised operator account changes policy           | Sensitive operations require fresh MFA (step-up within last 5 minutes). High-impact policy changes (anything affecting `admins`, `wheel`, or root SSH) require a second approver via the UI.     |
| Backup tampering                                      | Backups are signed and encrypted with a key that no operator account holds. Restore requires presenting the offline key.                                                                           |
| An approval is replayed, or granted for one thing and spent on another | ⭐ Added 2026-09-04. "A distinct approver approved something" is not enough. An approval binds to the normalized operation, the requester, the target, a hash of the parameters or content, the policy revision in force, an expiry and a single-use nonce, and altering any of them voids it. Without that, A is approved and B is executed, or A is mutated after approval and before use. The same binding applies to policy publication, agent escalation requests, break-glass and restore. **Status: NOT MODELLED**, the approver-count and no-self-approval half is built in `policies/governance/require_approval.rego`, the binding half is not. |
| The secrets store is unsealed, dumped or restored by the wrong person | ⭐ Added 2026-09-04. OpenBao is a trust boundary and was not described as one anywhere. Unseal shares and root or recovery tokens split across people, never resident on the store's own host, never inside the deployment's own backup, and no root token left in a file or an environment variable by bootstrap. Total loss of the store is a rehearsed recovery path rather than an outage nobody has tried. **Status: NOT MODELLED.** |
| A restore resurrects a revoked credential or a deleted account | ⭐ Added 2026-09-04, extending the backup row above, which covers tampering with a backup and not the act of restoring one. Restore is itself a security event: authorized, audited and anchored like any other. FreeIPA, Postgres, Keycloak and the audit chain restore to a consistent point in a stated order, and every credential revoked between the snapshot and the restore is re-revoked as part of the procedure. The procedure is exercised on a cadence, because an untested restore is a claim. **Status: NOT MODELLED.** |
| Recordings and audit entries are read, kept or exported by people who should not | ⭐ Added 2026-09-04. This is the most sensitive data the product holds. Encryption at rest, a retention period with real deletion at the end of it, an audit entry for every view and every export, and a stated position on redaction. Reading a recording is itself a recorded act. **Status: PARTIAL**, `recordings.list` and `recordings.read` are policy-gated; retention, deletion, export logging and redaction are not built. See TMSR-03 and TMSR-04. |
| Operator pivots from API gateway host to FreeIPA host | Control plane components run on separate hosts (or at minimum, separate user namespaces with no shared sockets). The API gateway service account has no SSH access to other control plane hosts.   |

### Cross-cutting: what every other row in this section rests on

⭐ Added 2026-09-04, after an outside reader worked through the published corpus. Each of these sat
underneath rows above and was written down nowhere, and a control that is only implicit is not in the
contract. The requirement holds whatever the status says.

| Vector | Required control |
| ------ | ---------------- |
| A clock is rolled back, or NTP is answered by an attacker | Kerberos ticket validity, X.509 and SSH certificate lifetimes, JWT expiry, MFA freshness (`step_up_mfa_max_age`), enrollment-token expiry, bundle TTL and anchor liveness are every one of them clock-dependent, and a host that controls its own clock controls all of them locally. Time comes from an authenticated source, NTS or NTP restricted to the control plane. The gateway refuses an assertion whose issue time falls outside a bounded skew from its own. A host whose clock cannot be trusted fails the decision rather than being handed a stale `max_age` for free. **Status: NOT MODELLED.** Nothing in this document previously said where time comes from. |
| A disabled account, removed group, revoked certificate or withdrawn grant keeps working | One table, and it does not exist yet: for user disablement, group removal, Kerberos TGT, access JWT, refresh token, SSH user certificate, SSH host certificate, host X.509, SSSD cache, OPA bundle, VPN profile and RADIUS client, the maximum time each stays effective after revocation and the behaviour of each while its authority is unreachable. Nothing may be described as immediate unless a mechanism makes it so. Short lifetimes are a bound on damage, not a revocation path. **Status: NOT MODELLED.** Individual TTLs are configured in several places and no row states the sum of them. |
| An operator-configurable destination is pointed somewhere else and adamance authenticates to it | The `secret_ref` rule from the RADIUS module is the general rule and not a RADIUS one. Every outbound destination an operator can configure — anchor sinks (git, email, SSH or SCP, object store), webhooks, SMTP, package sources, the OIDC issuer, Wazuh, and AD or LDAP endpoints — resolves its credential from a name the code owns rather than a path or URL taken from a row, refuses link-local and cloud-metadata addresses, does not follow a redirect to another host, and re-validates at the moment of use because validating on write is only sound while writes are the only way rows appear. **Status: PARTIAL.** Held for AD (`adsecrets`) and RADIUS (`radiussecrets`), which is where it was discovered. Unstated everywhere else. See [`THREAT_MODEL_network_modules.md`](THREAT_MODEL_network_modules.md). |
| Two names that are equal in one layer and different in another | One canonical form for a principal, defined once: case folding, Unicode normalization, realm and FQDN handling, and the mapping between the Keycloak subject id, the FreeIPA DN, the Samba SID and the SSH principal. An account deleted and recreated under the same name is a different subject. Authorization keys on the stable identifier and never on the display name. **Status: NOT MODELLED**, and it is the failure mode that kills identity products: two strings that one layer calls equal and another does not. |
| Storage fills and the control plane stops deciding | Every store an unprivileged actor can grow — recordings, audit entries, Wazuh data, spool directories — has a quota and a stated behaviour at the limit, and that behaviour is refusal rather than silent loss. A session that cannot be recorded is already refused; an audit entry that cannot be written gets the same direction. **Status: PARTIAL.** |
| An unauthenticated or low-privilege caller exhausts the gateway | Connection and request caps, bounded request bodies, bounded OPA evaluation time, per-IP and per-principal limits on the expensive routes, and a bound on LDAP group sizes that a single decision will expand. The `/oauth/token` limiter is per IP and the Keycloak failure counter is per account, so a spray distributed across many source addresses and many accounts is under both. **Status: PARTIAL.** Denial of service is the least-covered category in this document and that was not a decision anyone made. |
| Losing a dependency changes the answer and nobody wrote down which way | For each of OPA, FreeIPA, Postgres, Keycloak and the anchor sink, this document states whether losing it fails open or closed. Undeclared is the same as unknown, and unknown at the moment of an outage is decided by whoever wrote the error path. **Status: NOT MODELLED.** |


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

#### Exposed admin UI / API on the public internet
**Required control:** V1 is private/VPN-only; bind to private network / VPN; no public internet exposure.

**As-built:** ✅ CONFIRMED.

`src/api-gateway/cmd/server/main.go` binds two listeners:
- `ListenHTTP` (plaintext, unauthenticated), intended for health/readiness probes only.
- `ListenMTLS` (TLS, service-to-service), for managed hosts and service mesh.

There is no `ListenPublic` or equivalent. The admin UI is served by a separate `admin-ui` service behind
the reverse proxy. No component binds to `0.0.0.0` with a port documented as publicly reachable.
The `Caddyfile` (per `scripts/dev-up.sh` and M1 artifacts) is the internet-facing boundary.

**Finding:** NONE. Control is implemented as described.

---

#### Credential stuffing against admin UI
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
  labelled by `web/admin-ui/src/lib/approverproofs.ts:96`), and as an unbuilt DRAFT design.
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

#### Phishing of admin session cookie
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

#### Vulnerable upstream container image
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

#### Direct exposure of LDAP/Kerberos ports
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

⚠ Corrected 2026-09-01: this passage sent the reader to `deploy/docker-compose.yml`, which git has never
contained. The top of `deploy/` has only ever held per-concern compose files; today `docker-compose.ha.yml`
(renamed from `docker-compose.t2.yml`), `docker-compose.keycloak.yml` and `docker-compose.siem.yml`, with the
rest under `deploy/dev/`, `deploy/observability/` and `deploy/setup/`.

---

### Enrollment (A1, A2)

#### Unauthorized host joining the domain
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

---

#### MITM of the install script
**Required control:** Install artifact served over TLS only, from a pinned hostname, SHA-256 published.

**As-built:** ✅ CONFIRMED.

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

#### Replay of an enrollment token
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

#### Hostname spoofing during enrollment
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

#### Compromised host uses its keytab to authenticate as another host
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

#### Theft or misuse of the SSH CA signing key
**Required control:** SSH CA is a separate trust chain from Dogtag (CRYPTO-07); signing key in Vault Transit
or sealed offline file; short-lived certs; CRL distribution for revocation.

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

#### Compromised host modifies its own audit logs to hide activity
**Required control:** ⚠️ **Restated 2026-09-02.** This read "Wazuh agent forwards logs in real time.
Local log tampering is detected by FIM and raises a high-severity alert", and FIM is not wired anywhere
(TM-12). The control is that the record of a privileged action does not live on the host it describes:
it is written to the hash-chained audit store on the control plane, and a signed anchor of the head
leaves the box. A host tampering with its own local logs does not reach either.

**As-built:** ⚠️ PARTIAL, and weaker than this document previously claimed. adamance does **not**
install the Wazuh agent on managed hosts; the agent binary is operator-provided. A host without one is
still fully governed (nothing gates on `wazuh_agent_status`) but forwards **no** logs to the SIEM, so
this control is absent on any such host rather than merely unverified.

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

#### Compromised host pulls sensitive policies it shouldn't see
**Required control:** OPA bundles are scoped per host group. Bundle requests authenticated with host cert.

**As-built:** 🔴 **REFUTED 2026-08-31. This row previously read "✅ CONFIRMED / Finding: NONE" and
that was false.** It is corrected in place rather than deleted, because a threat-model row that
recorded a control as *verified* when nothing implemented it is itself the most important finding
here: every later reader took it as an audit result.

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

#### Compromised host abuses its sudo rights to escalate
**Required control:** sudo rules are scoped narrowly. Sudo invocations are audit-logged centrally and
trigger alerts on anomaly.

**As-built:** ⚠️ DESIGN-ONLY; the sudo rules themselves are in the OPA policies (`policies/`), which
were not reviewed in this pass. The agent's `hostconfig/sssd.go` configures SSSD which reads HBAC/sudo
rules from FreeIPA. The audit emission from sudo events depends on Wazuh's syslog/auditd integration.

**Finding:** TM-13 (INFO); sudo policy scoping is as-designed (OPA + FreeIPA HBAC). Audit of sudo
events depends on Wazuh syslog/auditd configuration on managed hosts, which is outside the adamance
agent's scope (it's host OS configuration).

---

#### Stolen user TGT used from another host
**Required control:** Tickets bound to addresses where possible. Short ticket lifetime (8h default;
1h for admin principals). Renewal requires re-auth past max renewable lifetime (24h).

**As-built:** ⚠️ NOT VERIFIED IN CODE. Kerberos configuration lives in SSSD config (`src/client-agent/internal/hostconfig/sssd.go`)
and FreeIPA's KDC config. The specific `krb5_lifetime` and `max_life` per-principal settings were
not confirmed in this pass.

**Finding:** TM-14 (LOW). Kerberos ticket lifetime enforcement should be verified against the actual
`krb5.conf` or SSSD domain configuration generated by the agent.

---

### Policy bypass (A3)

#### User exploits a gap in a policy that wasn't `default deny`
**Required control:** All OPA decision documents and FreeIPA HBAC rules are default-deny. Verified by
policy unit tests in CI.

**As-built:** ⚠️ PARTIALLY REVIEWED. Two bugs found and fixed during this pass. See TM-15 findings below.

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

#### User races between policy update and enforcement
**Required control:** Local OPA decisions on the host. Bundle TTL ≤ 60s for security-critical policies.
Push-on-change via webhook for highest-impact policies.

**As-built:** ⚠️ PARTIAL.

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

#### Policy change introduces a vulnerability that ships before review
**Required control:** Policy changes go through git → CI (rego unit tests, opa eval against fixtures) →
review (one approver minimum; two for policies touching admin groups or root access) → signed bundle build.

**As-built:** ✅ CONFIRMED. CI pipeline added in this pass.

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

#### Operator with API access silently escalates a user
**Required control:** All write operations to FreeIPA and OPA are logged to Wazuh tagged with operator
identity. Logs are write-only from the operator's perspective.

**As-built:** ✅ CONFIRMED (design), ⚠️ NOT VERIFIED (Wazuh log sink configuration).

Every handler in `src/api-gateway/internal/handlers/` calls `auditFn()` with the operator identity from
the session. The `src/common/audit` package formats audit events consistently. Whether these events
reach Wazuh (vs. stdout only in dev mode) depends on the deployment's log routing configuration, which
was not reviewed.

**Finding:** TM-18 (RESOLVED); `WazuhEmitter` confirmed routing to Wazuh indexer via OpenSearch bulk API. Both dev stack and the single-host package wire `WAZUH_INDEXER_URL`. StdoutEmitter fallback when not configured; no silent audit drop.

---

#### Compromised operator account changes policy
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

#### Backup tampering
**Required control:** Backups signed and encrypted with a key no operator account holds. Restore requires
presenting the offline key.

**As-built:** ⚠️ RUNBOOK EXISTS, KEY MANAGEMENT NOT VERIFIED.

A restore runbook exists and references the offline backup key. The signing ceremony
is documented. The actual key storage location (USB in safe, HSM, etc.)
is an operational decision not captured in code. This is acceptable; the runbook correctly states
the requirement.

**Finding:** NONE. Operational gap, not an implementation gap.

---

#### Operator pivots from API gateway host to FreeIPA host
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

---

### Cryptographic baseline

#### TLS 1.3 only
**As-built:** ⚠️ PARTIAL CONFIRMATION.

`src/api-gateway/internal/config/config.go` TLS section was not reviewed in this pass. The design
states TLS 1.3 only. The Go `crypto/tls` library is configured via `tls.Config` in main.go. The
minimum version setting was not confirmed in this pass.

**Finding:** TM-21 (RESOLVED). Confirmed: `src/common/mtls/tlsconfig.go` sets `MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13`. The mTLS server uses `BuildServerConfig`. TLS 1.2 is rejected. No changes required. See **TM-21** HANDOFF.

#### Internal service clients use TLS 1.2
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

#### JWT: EdDSA only
**As-built:** ✅ CONFIRMED.

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

#### Password hashing: Argon2id
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

| ID    | Decision                                             | Proposed direction                                                                                        | Owner                                     |
| ----- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| TM-01 | HA model for FreeIPA                                 | Multi-master replication across 2+ nodes; documented failover runbook                                     | -    |
| TM-02 | Where does the OPA bundle live and how is it served? | Built in CI, signed offline, served by the API gateway over mTLS, cached locally on each agent            | -             |
| TM-03 | Audit log retention and immutability                 | 90 days hot in Wazuh indexer; 1 year cold in object storage with object lock                              | -           |
| TM-04 | Break-glass procedure for total directory loss       | Offline-encrypted root credentials in a sealed envelope; procedure documented (resolved). Remaining gap is only the operational runbook copy. | - |
| TM-05 | MFA enrollment flow and recovery                     | TOTP + WebAuthn; recovery codes printed once; admin can reset MFA only with second-approver MFA challenge | -        |
| TM-06 | Rate limiting on `/oauth/token` endpoint | ✅ RESOLVED: `OAuthTokenRateLimiter` (5 req/min per IP+UA) added to `ratelimit.go`. `OAuthTokenRateLimitMiddleware` wired in `main.go`. | api-gateway |
| TM-07 | Refresh token IP + User-Agent binding | ✅ RESOLVED: `RefreshTokenStore` in `session.go` enforces IP+UA binding. Single-use. Wired into `auth.TokenHandler`. Security events emitted on IP/UA mismatch. Integration tests in `src/api-gateway/internal/handlers/auth/token_integration_test.go`. | api-gateway |
| TM-08 | Digest pinning in docker-compose.yml | ✅ RESOLVED (2026-05-27): All images in `package/adamance/docker-compose.yml` (single-host) are now digest-pinned. `freeipa/freeipa-server:rocky-9-4.12.2@sha256:e1113f67eff871768aa6d2d5929911b28f9e45fd94c8cbecd491daca01f9d40e`, `openpolicyagent/opa:latest@sha256:541f92bc1b3077453b51e3ffc7f529be188bfab56d3600c5907b3e2cb85fb33e`, `wazuh/wazuh-indexer:4.8.0@sha256:42a563f4c94bf498b87fec9b583448f8509d920dc3b39c83f8857142367ccf47`, `wazuh/wazuh-manager:4.8.0@sha256:366f142ebb28920c41bf77af1dcded832a21e9d4ed9a63741656b43639592ca2`, `wazuh/wazuh-dashboard:4.8.0@sha256:ef94e02d31262364d4ea8e1166dda1106959de602aa24d9077628b68287f6b68`. `release.yml` `digest-check` job enforces no non-digest images in CI. `scripts/pin-digests.sh` automates digest updates. | deploy |
| TM-09 | Air-gapped installer distribution path               | Document the internal package repo as a V1.5 requirement. V1 acceptable with GitHub Releases. | docs |
| TM-10 | Host keytab scope in IPA API call | ✅ RESOLVED (M7.1 + M7.3): enrollment handler scopes `host_add` and `ipa-getkeytab` to a single host principal `host/<fqdn>@REALM`. (The multi-tenant/MSP extension is descoped, single-tenant V1; see TM-25.) | api-gateway |
| TM-11 | SSH CA signing key storage and key ceremony | ✅ RESOLVED: ceremony reviewed; as-built matches docs; checklist present; prod HSM is V1.5. | security |
| TM-12 | FIM monitoring of adamance agent log paths | ⚠ Corrected 2026-09-01: this row named `hostconfig/wazuh.go`, which has never existed. The agent's `ossec.conf` is written by `patchOssecConf` in `src/client-agent/internal/wazuh/register.go:219`, which overwrites the file with `<client>`, `<client_buffer>` and `<logging>` only (no `<syscheck>` stanza) and the fragment `writeWazuhConfig` writes (`src/client-agent/internal/enroll/enroll.go:422`) carries only a server address, port, protocol, hostname and enrollment key. So no adamance code emits a FIM watchlist: `policies/fim/policy.rego` would generate one but self-declares NOT WIRED with no runtime consumer, and `/var/log/adamance/` is not among `fim_monitored_paths` in `policies/data/global.json`. Read those two writers to confirm; any FIM of that path would have to come from manager-side config, which this repo does not carry (`deploy/dev/wazuh/config/ossec.conf` leaves syscheck to the image defaults). | client-agent |
| TM-13 | Sudo command audit via Wazuh syslog/auditd | Host OS-level configuration outside adamance agent scope. Document as a host hardening prerequisite. | docs |
| TM-14 | Kerberos ticket lifetime enforcement | Verify SSSD config generated by `hostconfig/sssd.go` sets `krb5_lifetime` and per-principal `max_life`. | client-agent |
| TM-15 | OPA policies default-deny review, IN PROGRESS | Partially done: core API authz, enrollment, SSH, sudo, lib/decision reviewed. Two bugs found and fixed (see below). CIS compliance policies not yet reviewed. Remaining: firewall, fim, data, governance packages. | policies |
| TM-16 | Bundle TTL for security-critical policies | ✅ RESOLVED: `bundle.critical.tar.gz` is now built by `release.yml` (Job: build-policies) and `policies-build.yml` (main branch). Served by `bundle.go` at `/policies/bundle.critical.tar.gz` with `CriticalMaxAge=60s` (≤60s per threat model). Critical bundle sources: `policies/firewall`, `policies/lib/decision.rego` (`policies/sudo` was REMOVED because sudo policy comes from FreeIPA; the build now FAILS if a listed critical source is missing). Signed with K-06 key. | api-gateway + policies |
| TM-17 | CI policy build pipeline verification | ✅ RESOLVED: `build-policies` job in `release.yml` runs regal lint, `opa test`, `opa eval` fixture regression, `opa build --signature-key`. `policies-build.yml` CI also covers this. `make verify-policies-bundle` target exists. | CI |
| TM-18 | Audit log sink verification for production | ✅ RESOLVED (2026-05-27): `WazuhEmitter` in `src/common/audit/wazuh.go` sends events to Wazuh indexer via OpenSearch bulk API (`/_bulk`) when `WAZUH_INDEXER_URL` is set; falls back to stdout when not configured so no audit events are silently dropped. Both dev stack (`deploy/dev/docker-compose.dev.yml`) and the single-host production package (`package/adamance/docker-compose.yml`) wire `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS` to api-gateway. Dev stack additionally passes `WAZUH_INDEXER_CA_CERT`. | deploy |
| TM-19 | Second-approver enforcement for high-impact policy changes | ✅ RESOLVED (2026-06-11, `b7051bcc`): `policies/governance/require_approval.rego` (decision `governance.require_approval`) ⚠️ **Corrected 2026-09-02: this read "2 distinct non-self approvers" and that is wrong.** `policies/governance/require_approval.rego:42-48`: `second_approver: false`, the default, requires **one** distinct approver, which is two-person control counting the requester. `true` requires two approvers, which is three-person control. The requester is never counted toward the total either way., `policy.Handler` in `src/api-gateway/internal/handlers/policy/handler.go`, approval store in `src/api-gateway/internal/storage/approval/store.go`, route at `src/api-gateway/cmd/server/main.go:4819`. ⛔ **NOT graceful degradation, it fails CLOSED**: `src/api-gateway/internal/handlers/policy/handler.go:365` refuses the publish when the rule is not loaded. The legacy `governance.require_second_approver` never compiled and left this gate fail-OPEN; it was retired. Migration: `src/api-gateway/internal/db/migrations/0008_policy_change_approvals.sql` (renumbered from `002_policy_approvals` by the 2026-06-15 consolidation). | api-gateway |
| TM-20 | single-host topology and the operator-pivot control | ✅ RESOLVED: single-host exemption documented in threat model. | threat model |
| TM-21 | TLS 1.3 enforcement in api-gateway Go server | ✅ RESOLVED: `src/common/mtls/tlsconfig.go` sets `MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13`. TLS 1.2 rejected. | api-gateway |
| TM-22 | Argon2id for locally-managed password hashing | ✅ RESOLVED: No direct password storage in api-gateway. All auth delegates to FreeIPA. Compliant by design. | api-gateway |
| TM-23 | Internal service clients use TLS 1.2 instead of TLS 1.3 | ✅ RESOLVED (2026-05-27): the 8 api-gateway/wazuh-bridge clients → `MinVersion: tls.VersionTLS13`. **2026-07-11 re-verification caught a residual the "no VersionTLS12 in src/" claim missed: the client-agent join bootstrap (`enroll/join.go`, 3 paths) still allowed TLS 1.2 → fixed to `tls.VersionTLS13` (commit `574dfad`). Now genuinely zero `VersionTLS12` in `src/`.** | api-gateway + wazuh-bridge + client-agent |
| TM-24 | (reserved) | | | |
| TM-25 | Tenant isolation at the FreeIPA layer (NF-1) | ⛔ **N/A for V1, multi-tenancy was REMOVED.** adamance is single-tenant for V1 (never-MSP decision); the multi-tenant backend was deleted (`0248ebb`), so there is no per-tenant attack surface in V1. The `tenants` table is retained ONLY as the Sites FK-anchor to a single default tenant. The per-tenant Kerberos-principal isolation design is a **V2** concern and is NOT wired for V1. (Historical: it superseded the S-15 `{"TenantID": …}` option-key approach FreeIPA silently discarded.) | V2 (deferred) |
| TM-26 | Trusted time | ⭐ OPEN (2026-09-04). Every lifetime, expiry and freshness check in this document trusts a clock nobody authenticated. Direction: NTS or control-plane-restricted NTP, a bounded skew check at the gateway, and a decision that fails rather than ages gracefully when a host's clock is not trustworthy. | control plane + agent |
| TM-27 | Revocation convergence | ⭐ OPEN (2026-09-04). No single statement of how long a revoked credential keeps working, per credential type, or what happens while its authority is unreachable. Direction: one table covering all twelve credential types, with a measured bound each. | control plane |
| TM-28 | SSH revocation reaches `sshd` | ⭐ OPEN (2026-09-04). `sshd` reads a KRL or `RevokedKeys`, not an X.509 CRL. Direction: prove what `handlers/sshca/crl.go` serves is consumed by `sshd`, or build the KRL path, and measure the convergence. | api-gateway + agent |
| TM-29 | Approval binding, replay and TOCTOU | ⭐ OPEN (2026-09-04). Approvals count approvers and do not bind to what was approved. Direction: bind to normalized operation, requester, target, content hash, policy revision, expiry and a single-use nonce, across policy publish, agent escalation, break-glass and restore. | policies + api-gateway |
| TM-30 | Audit completeness and mutation atomicity | ⭐ OPEN (2026-09-04). The chain proves nothing was altered; nothing proves everything was written. Direction: intent before mutation, outcome after, an explicit unconfirmed state, reconciliation, and a failed append that fails the operation. | api-gateway + audit |
| TM-31 | Anchor signing key and its trust root | ⭐ OPEN (2026-09-04). Anchors are described as signed and the signing key is named nowhere. Direction: name the key, the algorithm, the verifier's trust root, distribution, rotation and compromise recovery. If it is the HMAC chain key, anyone who can verify can forge. | audit anchoring |
| TM-32 | Off-box preservation, not just off-box witness | ⭐ OPEN (2026-09-04). Only the chain head leaves the box, so destruction of the local store is provable and not recoverable. Direction: state the distinction plainly, and decide whether the full event stream ships to immutable storage. | audit anchoring |
| TM-33 | Console web surface | ⭐ OPEN (2026-09-04). OIDC flow parameters, rendering of attacker-supplied strings, and object-level authorization were never modelled. Direction: PKCE/state/nonce/exact redirect, CSP with no inline script, per-object authorization and field allowlists on write. | admin-ui + api-gateway |
| TM-34 | Enrollment lifecycle beyond first join | ⭐ OPEN (2026-09-04). CA bootstrap trust, token entropy and handling, SAN rather than CN, proof of possession, host cloning, re-enrollment and decommission. | api-gateway + client-agent |
| TM-35 | Availability and fail direction | ⭐ OPEN (2026-09-04). Resource exhaustion is the least-covered category here, and no component states whether losing a dependency fails open or closed. | all |
| TM-36 | Secrets store as a trust boundary | ⭐ OPEN (2026-09-04). OpenBao appears in the README and in no threat model. Unseal shares, root and recovery tokens, bootstrap, backup and total-loss recovery. | deploy + api-gateway |
| TM-37 | Restore as a security event | ⭐ OPEN (2026-09-04). Backup tampering is modelled; restoring is not. A restore can resurrect a revoked credential or a deleted account. | deploy + control plane |
| TM-38 | Identity canonicalization | ⭐ OPEN (2026-09-04). No single canonical principal form across Keycloak, FreeIPA, Samba and SSH. | control plane |
| TM-39 | Recording and audit privacy | ⭐ OPEN (2026-09-04). Encryption at rest, retention with real deletion, view and export auditing, redaction. See TMSR-03 and TMSR-04. | api-gateway + storage |
