# Threat Model: adamance

> Status: **DRAFT → REVIEWED** — second pass against as-built system + V1 verification pass. Owner: security architecture.
> Last reviewed: **2026-07-11** (V1 verification — see ⭐ section below). Prior: 2026-05-26, 2026-05-24.

---

## ⭐ V1 verification pass (2026-07-11) — reconciled against live code (AUTHORITATIVE)

The **2026-05-26 narrative body below is a point-in-time as-built audit**. Many items it flags as gaps
("❌ VIOLATION", "HARD STOP: MISSING IMPLEMENTATION", "stub", "NOT IMPLEMENTED") were fixed in the weeks
after and the "Open decisions" table (updated through 2026-06-03) marks them RESOLVED — but the narrative
paragraphs were never updated, so the doc contradicts itself. This pass re-verified each contested item
against the current source. **Where this section and the older narrative disagree, THIS section wins.**

**Verified RESOLVED (narrative is stale; do not be alarmed by the ❌/HARD-STOP language below):**

| TM | Contested claim (old narrative) | Live ground truth (2026-07-11) |
|----|----|----|
| TM-10 | "enrollment handler is a stub, never calls FreeIPA" | FALSE — `enrollment/handler.go` calls `HostAdd`/`GetKeytab`/`IssueHostCert` (:514/533/547); join redeem does the same. Fully wired. |
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
  brute-force protection**. **Fixed** — the production realm template
  (`deploy/setup/keycloak/realm-adamance.json.tmpl`) now sets `bruteForceProtected:true`,
  `failureFactor:10`, temporary lockout (`permanentLockout:false`, `maxFailureWaitSeconds:900`). (Dev
  provisions its realm separately and additionally has the OIDC 5/min per-IP rate limit.)

**Confirmed DEFERRED-BY-DESIGN for V1 (genuine, documented, acceptable — not "broken"):**
- **TM-09 air-gapped / no-GitHub installer** — being CLOSED right now: the gateway now serves the
  agent binary itself (fail-closed Ed25519), replacing GitHub Releases (see the turnkey-install work).
- **TM-11 residual** (HSM/Vault-Transit signer → V1.5), **TM-20** (operator↔control-plane pivot: N/A on
  single-host), **TM-25** (per-tenant IPA isolation → V2), **TM-12** (Wazuh FIM of the agent's own
  logs → V1.5; Wazuh is stub in V1), **TM-13** (central sudo-event audit = host-OS config), B1 (public
  WAF/allowlist → V1.5; V1 is private/VPN-only, SCOPE-10). Network exposure of FreeIPA LDAPS/Kerberos
  ports is REQUIRED for managed-host SSSD and is bounded by the VPN perimeter (SCOPE-10).

**Still genuinely open (low / informational):** TM-15 CIS-policy default-deny review (compliance-suite
audit, distinct from the authz default-deny review which IS done); TM-01/02/03/05 architecture
open-decisions (HA model, bundle distribution, audit retention, MFA recovery — track to closure).

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
| 3    | SSH CA private key (step-ca, K-05)                   | Issue SSH certificates impersonating any user to any host (PAM_STACK.md rates compromise "Catastrophic"); separate chain from Dogtag per CRYPTO-07 |
| 4    | Directory admin credentials (`cn=Directory Manager`) | Create/escalate accounts, modify group membership, disable policy                     |
| 5    | OPA bundle signing key                               | Push arbitrary policy to every managed host (e.g. allow any SSH)                      |
| 6    | API gateway JWT signing key                          | Forge admin sessions without touching the directory                                   |
| 7    | Postgres transactional store (MFA evidence, refresh tokens, enrollment tokens; DATA-02) | Forge fresh-MFA state to bypass every step-up gate, exfiltrate refresh/enrollment token hashes, replay enrollment |
| 8    | Wazuh agent enrollment key                           | Log spoofing, alert suppression, blind the SIEM                                       |
| 9    | Operator MFA recovery codes                          | Bypass MFA on operator accounts                                                       |
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

## Adversaries

We design explicitly against four threat actor profiles.

### A1 — External unauthenticated attacker

**Access:** network reachability to whatever the deployment exposes. **Goal:** any foothold. **Capability:**
opportunistic port scanning, public exploits, credential stuffing, phishing. **Not capable of:** zero-day exploits in
upstream components; cryptographic breaks.

### A2 — Compromised managed host

**Access:** root on a host that was enrolled legitimately. **Goal:** lateral movement, persistence, privilege escalation
across the fleet. **Capability:** full control of a Linux box including its host keytab, the local SSSD cache, and any
user tickets that touch the host. **Realistic vector:** unpatched application, supply-chain compromise, stolen developer
SSH key.

### A3 — Malicious or compromised user

**Access:** valid credentials for some user account (could be a low-privilege user, could be an operator). **Goal:**
access beyond their authorization, exfiltration, or destruction. **Capability:** whatever the account legitimately can
do; social engineering of other users; abuse of any policy gap.

### A4 — Insider with control plane access

**Access:** legitimate operator account on one or more control-plane components. **Goal:** usually mistakes (most
common), occasionally malicious. **Capability:** depends on operator role; in the worst case, root on the FreeIPA host.

## Attack vectors and required controls

Each row is a documented threat plus the control(s) that address it. The control column drives implementation
requirements; if it's not built, the threat is open.

### Initial access (primarily A1)

| Vector                                        | Required control                                                                                                                                                                  |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Exposed admin UI / API on the public internet | V1 is private/VPN-only (SCOPE-10, Locked) — bind to the private network / VPN (e.g. WireGuard, Tailscale); no public internet exposure. The public-exposure path (reverse proxy with WAF, IP allowlist) is **V1.5+** forward-looking design, not a V1 path. |
| Credential stuffing against admin UI          | MFA required for **all** admin accounts (FreeIPA OTP or WebAuthn). Rate limit on `/oauth/token`. Account lockout after N failed attempts with exponential backoff.                |
| Phishing of admin session cookie              | Short JWT lifetime (≤15m), refresh tokens bound to IP and User-Agent, MFA step-up required for sensitive operations (user creation, policy change, machine enrollment).           |
| Vulnerable upstream container image           | Pin all images by digest, not tag. Weekly Trivy scan in CI with a blocking severity threshold. Documented monthly patch cadence with emergency channel for CVEs ≥ 9.0.            |
| Direct exposure of LDAP/Kerberos ports        | Only the reverse proxy is in the edge zone. LDAPS/Kerberos are not reachable from outside the control plane subnet.                                                               |

### Enrollment (primarily A1, A2)

| Vector                               | Required control                                                                                                                                                                                                 |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unauthorized host joining the domain | Enrollment requires a **one-time scoped token** issued by an authenticated admin, bound to an expected hostname, expiring within 24 hours. No anonymous enrollment. No `1515/authd` exposed without prior token. |
| MITM of the install script           | Install artifact is served over TLS only, from a pinned hostname, with a published SHA-256 checksum. Production deployments distribute via an internal package repository, not `curl \| bash`.                   |
| Replay of an enrollment token        | Tokens are single-use and consumed atomically by the API. Token use is logged with the source IP and resulting host principal.                                                                                   |
| Hostname spoofing during enrollment  | The enrolling host must present a CSR for the hostname declared in the token. The CA refuses to sign for a name not in the token.                                                                                |

### Lateral movement (primarily A2)

| Vector                                                           | Required control                                                                                                                                                                        |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Compromised host uses its keytab to authenticate as another host | Host keytabs grant only the host's own identity. No transitive trust. User SSH uses **ephemeral certificates** issued by the internal SSH CA (step-ca, ARCH-05 — see `PAM_STACK.md`); host credentials are not accepted for user-initiated SSH. |
| Theft or misuse of the SSH CA signing key (issue rogue user certs) | SSH CA (step-ca, K-05) is a separate trust chain from Dogtag (CRYPTO-07); signing key home is Vault Transit / sealed offline file. Certs are short-lived; revocation/CRL distribution and CA-key-compromise threats are enumerated in `PAM_STACK.md` §"Threats addressed and not". |
| Compromised host modifies its own audit logs to hide activity    | Wazuh agent forwards logs in real time. Local log tampering is detected by FIM and raises a high-severity alert. Critical events trigger immediate active response.                     |
| Compromised host pulls sensitive policies it shouldn't see       | OPA bundles are scoped per host group. A host pulls only the policies it's targeted by. Bundle requests are authenticated with the host certificate.                                    |
| Compromised host abuses its sudo rights to escalate              | sudo rules are scoped narrowly (specific commands, not `ALL=(ALL)`). Sudo invocations are audit-logged centrally and trigger alerts on anomaly.                                         |
| Stolen user TGT used from another host                           | Tickets are bound to addresses where possible. Short ticket lifetime (8h default per SSSD `krb5_lifetime`; 1h target for admin principals, enforced via per-principal KDC policy `max_life` — see SECURITY_ARCHITECTURE.md §Cryptographic standards). Renewal requires re-auth past max renewable lifetime (24h). |

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
| Compromised operator account changes policy           | Sensitive operations require fresh MFA (step-up within last 5 minutes). High-impact policy changes — anything affecting `admins`, `wheel`, or root SSH — require a second approver via the UI.     |
| Backup tampering                                      | Backups are signed and encrypted with a key that no operator account holds. Restore requires presenting the offline key.                                                                           |
| Operator pivots from API gateway host to FreeIPA host | Control plane components run on separate hosts (or at minimum, separate user namespaces with no shared sockets). The API gateway service account has no SSH access to other control plane hosts.   |

### Cryptographic baseline

These are non-negotiable defaults; deviation requires explicit documentation:

- TLS: 1.3 only. No 1.2 fallback. Cipher suites limited to AEAD (AES-GCM, ChaCha20-Poly1305).
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

## Open decisions — recorded at the end of this document

The authoritative table is **[Open decisions](#open-decisions)**, in the second-pass review below.

A duplicate copy of it stood here until 2026-08-03, carrying TM-01 through TM-05 with byte-identical
text. The later table is a strict superset (TM-01 through TM-25) and records which decisions have since
been RESOLVED, so the copy here could only ever go stale against it — two tables of the same IDs is how
a document drifts from itself. It was removed rather than reworded; nothing was lost, because every row
it held is still in the authoritative table verbatim.

## Revision history

| Date       | Change        | Author |
| ---------- | ------------- | ------ |
| 2026-05-24 | Initial draft | —      |
| 2026-05-26 | Second pass against as-built system (M5 complete). Verified all required controls are implemented. Added TM-06 through TM-10 for identified gaps and alignment issues. | —      |
| 2026-07-11 | V1 verification pass — re-verified every contested TM item against live source (see the ⭐ section at top). Fixed 2 real residuals (client-agent join TLS 1.2→1.3; Keycloak brute-force protection). Reconciled the stale 2026-05-26 narrative vs. the resolution table. Fixed malformed markdown in the Revision-history + Open-decisions tables. Descoped TM-25 (multi-tenancy removed for V1). | Claude (Opus) |

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
**Required control:** V1 is private/VPN-only — bind to private network / VPN; no public internet exposure.

**As-built:** ✅ CONFIRMED.

`src/api-gateway/cmd/server/main.go` binds two listeners:
- `ListenHTTP` (plaintext, unauthenticated) — intended for health/readiness probes only.
- `ListenMTLS` (TLS, service-to-service) — for managed hosts and service mesh.

There is no `ListenPublic` or equivalent. The admin UI is served by a separate `admin-ui` service behind
the reverse proxy. No component binds to `0.0.0.0` with a port documented as publicly reachable.
The `Caddyfile` (per `scripts/dev-up.sh` and M1 artifacts) is the internet-facing boundary.

**Finding:** NONE. Control is implemented as described.

---

#### Credential stuffing against admin UI
**Required controls:** MFA required for all admin accounts; rate limit on `/oauth/token`; account lockout
after N failed attempts with exponential backoff.

**As-built:** ⚠️ PARTIAL.

- MFA requirement: ✅ CONFIRMED. `src/api-gateway/internal/session/session.go` validates MFA via
  `mfa_verified` claim in the JWT. `src/api-gateway/internal/middleware/mfa.go` (referenced in main.go
  setup) enforces step-up. The FreeIPA backend is configured for OTP/WebAuthn.
- Rate limiting on `/oauth/token`: ✅ RESOLVED. `src/api-gateway/internal/middleware/ratelimit.go` adds `OAuthTokenRateLimiter` (5 req/min per IP+User-Agent, keyed by SHA256(IP+UA)). `OAuthTokenRateLimitMiddleware` is wired into the router in `main.go`. Rate-limit events are emitted as structured audit events. See **TM-06** HANDOFF.
- Account lockout after N failed attempts: ❓ NOT FOUND. No lockout logic in `src/api-gateway/`. FreeIPA
  may apply its own (not verified in code). This is a gap for the API gateway layer.

---

#### Phishing of admin session cookie
**Required controls:** Short JWT lifetime (≤15m); refresh tokens bound to IP and User-Agent; MFA step-up
required for sensitive operations.

**As-built:** ⚠️ PARTIAL.

- JWT lifetime ≤ 15m: ✅ CONFIRMED. `src/api-gateway/internal/config/config.go` defaults `TTLMinutes: 15`.
  Line 137: `if c.JWT.TTLMinutes == 0 { c.JWT.TTLMinutes = 15 }`.
- Refresh token bound to IP and User-Agent: ✅ RESOLVED. `src/api-gateway/internal/session/session.go` adds `RefreshTokenStore` with IP+UA binding enforcement. `Validate()` rejects on IP mismatch or UA mismatch. Single-use (consumed after validation). Security events emitted on mismatch (`auth.refresh.fail` with IP and UA). Wired into `auth.TokenHandler` in `src/api-gateway/internal/handlers/auth/token.go`. HTTP-layer integration tests in `src/api-gateway/internal/handlers/auth/token_integration_test.go`. See **TM-07** HANDOFF.
- MFA step-up for sensitive operations: ✅ CONFIRMED. The `authz.RequireMFA()` middleware is applied to
  sensitive endpoints (enrollment token creation, policy publish, user modification, SSH CA operations).
  The OPA decision `adamance.api.authz` returns `mfa_step_up` as an obligation.

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
  The single-host package (`package/adamance/docker-compose.yml`) still contains non-digest images
  (`freeipa/freeipa-server:rocky-9-4`, `openpolicyagent/opa:latest`, `wazuh/*:4.8.0`) that must
  be resolved and pinned before production use.
- Trivy scan in CI: `release.yml` includes Trivy scanning of container images with blocking
  severity threshold (HIGH/CRITICAL).
- Monthly patch cadence: documented in `RELEASE.md` and the design docs.

**Finding:** TM-08 (RESOLVED) — `deploy/dev/docker-compose.dev.yml` uses sha256-pinned images. single-host package (`package/adamance/docker-compose.yml`) fully resolved: all 5 images are now digest-pinned with `@sha256:`.

---

#### Direct exposure of LDAP/Kerberos ports
**Required controls:** Only the reverse proxy is in the edge zone. LDAPS/Kerberos are not reachable from
outside the control plane subnet.

**As-built:** ⚠️ NOT VERIFIED.

The Docker Compose network configuration was not reviewed in this pass. `docker-compose.yml` was not present
in the root. The control plane network segmentation is documented in `SECURITY_ARCHITECTURE.md` §Network
policy but not verified against a running compose file. This should be verified against `deploy/docker-compose.yml`
or equivalent before first deployment.

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

**Finding:** TM-09 (NOTE) — The installer script currently downloads the binary from GitHub Releases at
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

**Finding:** TM-10 (LOW) — Confirm host keytab scope in the FreeIPA IPA API call during enrollment.

**Resolution:** ⚠️ DEFERRED — HARD STOP: MISSING IMPLEMENTATION (2026-05-27, red-team).

The enrollment handler does NOT call FreeIPA at all. It is a stub that validates a token, writes to the Postgres `machines` table, and returns `{status, hostname, host_group}`. No `ipa host_add`, no keytab generation, no host certificate issuance. The client-agent expects `{cert_pem, key_pem, keytab_b64, wazuh_key, host_dn, realm, domain, ipa_servers}` but receives none of these. The IPA integration (including proper single-host keytab scope) must be built before enrollment is functional.

---

#### Theft or misuse of the SSH CA signing key
**Required control:** SSH CA is a separate trust chain from Dogtag (CRYPTO-07); signing key in Vault Transit
or sealed offline file; short-lived certs; CRL distribution for revocation.

**As-built:** ⚠️ DESIGN CONFIRMED, IMPLEMENTATION NOT VERIFIED.

The PAM_STACK.md design is sound. `src/api-gateway/internal/handlers/sshca/crl.go` serves the CRL endpoint.
The `lac` CLI has `lac ssh-cert request` subcommand. However:
- The actual SSH CA signing key material (step-ca or equivalent) was not found in the `src/` tree.
  The SSH CA is described as living inside the API gateway or as a sibling service — the implementation
  path (`src/api-gateway/internal/sshca/`) exists as a handler package but the signing key management
  (where the private key lives and how it's used) was not verified.
- The OPA bundle signing key: `src/api-gateway/internal/bundle/bundle.go` handles bundle serving and
  signing verification, but the signing key location is not confirmed.

**Finding:** TM-11 (MEDIUM) — The SSH CA implementation (signing key storage, key ceremony,
 Vault/HSM integration) needs a dedicated security review before V1 ships. The runbook
 `docs/RUNBOOKS/ssh-ca-rotation.md` exists but the actual key storage path was not verified in this pass.

**Resolution:** ✅ RESOLVED — no implementation gap; documentation clarified (2026-05-27, red-team).

The runbook was reviewed against the as-built system and K-05 specification. The key ceremony checklist (lines 346–396) covers all seven phases with two-person integrity. The as-built procedure matches the documentation. K-05 storage is file-based on an offline signer (`/opt/adamance-signer/`), consistent with the dev tier and the M3.5 as-built. Production HSM/Vault Transit is a V1.5 aspiration.

---

#### Compromised host modifies its own audit logs to hide activity
**Required control:** Wazuh agent forwards logs in real time. Local log tampering is detected by FIM and
raises a high-severity alert.

**As-built:** ⚠️ PARTIAL — and weaker than this document previously claimed. adamance does **not**
install the Wazuh agent on managed hosts; the agent binary is operator-provided. A host without one is
still fully governed (nothing gates on `wazuh_agent_status`) but forwards **no** logs to the SIEM, so
this control is absent on any such host rather than merely unverified.

`src/client-agent/internal/wazuh/register.go` registers an **already-installed** agent with the Wazuh
manager and patches `ossec.conf` to point at it; registration is non-fatal and is skipped when no agent
is present. Where an agent does exist, enrollment and log forwarding work. Whether the Wazuh FIM module
monitors the adamance agent's own log paths (`/var/log/adamance/`) and alerts on tampering remains
unverified.

An earlier revision of this section cited `src/client-agent/internal/wazuh/install.go` as evidence that
adamance installed and configured the agent. That file was unreachable code — gated on a `wazuh_key` the
server never populated — and has been deleted. It never ran on any host, so the control it was cited as
evidence for was never delivered by that path. Recorded here because a threat model that cites
non-executing code as as-built evidence is worse than one that admits a gap.

**Finding:** TM-12 (LOW) — Confirm FIM monitors adamance agent logs on managed hosts.
**Finding:** TM-12b (MED) — This control depends on an operator-installed Wazuh agent. Either surface
per-host SIEM coverage so the gap is visible, or land the gateway-served pinned wazuh-agent package so
hosts obtain one automatically (backlog).

---

#### Compromised host pulls sensitive policies it shouldn't see
**Required control:** OPA bundles are scoped per host group. Bundle requests authenticated with host cert.

**As-built:** ✅ CONFIRMED.

`src/api-gateway/internal/bundle/bundle.go` serves bundles. `src/client-agent/internal/bundle/pull.go`
pulls bundles authenticated with the host mTLS certificate. Bundle scoping by host group is implemented
in the OPA bundle server (path-based or query-parameter-based targeting). The agent verifies bundle
signatures before applying.

**Finding:** NONE.

---

#### Compromised host abuses its sudo rights to escalate
**Required control:** sudo rules are scoped narrowly. Sudo invocations are audit-logged centrally and
trigger alerts on anomaly.

**As-built:** ⚠️ DESIGN-ONLY — the sudo rules themselves are in the OPA policies (`policies/`), which
were not reviewed in this pass. The agent's `hostconfig/sssd.go` configures SSSD which reads HBAC/sudo
rules from FreeIPA. The audit emission from sudo events depends on Wazuh's syslog/auditd integration.

**Finding:** TM-13 (INFO) — sudo policy scoping is as-designed (OPA + FreeIPA HBAC). Audit of sudo
events depends on Wazuh syslog/auditd configuration on managed hosts, which is outside the adamance
agent's scope (it's host OS configuration).

---

#### Stolen user TGT used from another host
**Required control:** Tickets bound to addresses where possible. Short ticket lifetime (8h default;
1h for admin principals). Renewal requires re-auth past max renewable lifetime (24h).

**As-built:** ⚠️ NOT VERIFIED IN CODE — Kerberos configuration lives in SSSD config (`src/client-agent/internal/hostconfig/sssd.go`)
and FreeIPA's KDC config. The specific `krb5_lifetime` and `max_life` per-principal settings were
not confirmed in this pass.

**Finding:** TM-14 (LOW) — Kerberos ticket lifetime enforcement should be verified against the actual
`krb5.conf` or SSSD domain configuration generated by the agent.

---

### Policy bypass (A3)

#### User exploits a gap in a policy that wasn't `default deny`
**Required control:** All OPA decision documents and FreeIPA HBAC rules are default-deny. Verified by
policy unit tests in CI.

**As-built:** ⚠️ PARTIALLY REVIEWED. Two bugs found and fixed during this pass. See TM-15 findings below.

**TM-15 Findings — Core policies reviewed:**

Policies confirmed with `default deny` from the start:
- `adamance.api.authz` — ✅ Default deny correct. Every operation has explicit allow rules.
- `adamance.enrollment.allowed` — ✅ Default deny correct. Super-admin allow, enrollment operator allow,
  host-already-enrolled deny, then explicit deny.
- `adamance.ssh.access` — ✅ Default deny correct. Super-admin allow, group-allowed SSH, then explicit denies
  for principal mismatch, outside access window, no group match.
- ~~`adamance.sudo.conditional`~~ — **REMOVED** (`DESIGN_sudo_policy_via_freeipa.md`); it was a placeholder nothing queried. Historic review below. ✅ Default deny correct. Super-admin allow, conditional rules, explicit denies
  for MFA stale, no MFA, approval-required, command not matched.
- `adamance.lib.decision` — ✅ `combine_decisions` correctly handles `allow=true` when all sub-decisions allow.
  The lib has no `default deny` of its own (it's a helper, not a policy package).

**Bug 1 (FIXED): `adamance.lib.decision.concat` — undefined on nested arrays**

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

**Bug 2 (FIXED): `adamance.sudo.conditional.subject_in_rule_groups` — inverted logic**

The helper was:
```rego
subject_in_rule_groups(rule) if {
    some sg in rule.subject_groups
    not sg in input.subject.groups
}
```
`some sg in X; not sg in Y` means "∃g∈X: g∉Y" — there exists a rule group not in the subject's groups.
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
"command not in any sudo rule" deny path — denying legitimate access incorrectly.

The existing test `test_subject_group_mismatch_denied` accidentally masked this bug: it tested
a subject NOT in any rule's groups, which the buggy logic returned `true` for, and then the
policy's final "command not matched" deny path produced the right outcome for the wrong reason.

Fix: corrected the `some` direction. Added `test_subject_in_rule_groups_should_match` to
`policies/sudo/conditional_test.rego` that specifically exercises the corrected direction and
asserts an `allow` outcome.

**Remaining review needed:**
- `policies/firewall/host.rego` — ✅ Reviewed. `default deny` correct. Single unconditional generation
  rule produces a full ruleset for any valid host group. Drop-by-default base rules, management-CIDR SSH
  fallback, agent connectivity preserved. No issues found.
- `policies/fim/policy.rego` — ✅ Reviewed. `default deny` correct. Single unconditional generation rule
  merges global FIM defaults with per-group additions via `array.concat`. No issues found.
- `policies/data/` — ✅ Data files (global.json, group data). Not authorization policy; reviewed as part of
  data schema. `step_up_mfa_max_age_seconds: 300` confirmed correct.
- `policies/governance/` — ✅ Scaffold only per its own README. No decision rules implemented yet.
- `policies/compliance/cis/` — 80+ files. Not reviewed in this pass (CIS benchmark audit, separate from
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

**Finding:** TM-16 (MEDIUM) — Bundle TTL default (300s) exceeds the ≤60s requirement for security-critical
policies stated in the threat model. Either the design needs to be updated or the implementation needs
a per-bundle TTL configuration that enforces ≤60s for SSH/sudo/admin policies.

**Resolution:** ⚠️ PARTIALLY RESOLVED (2026-05-27, orchestrator review).

`CriticalMaxAgeSec` added to `BundleConfig` and `CriticalMaxAge`/`CriticalBundlePath` added to the
bundle server `Config`. `ServeHTTP` now applies ≤60s TTL (configurable, default 60s) for requests to
`/policies/bundle.critical.tar.gz` (security-critical policies: sudo, firewall, admin-group), while
the default bundle serves at 300s TTL. Mechanism is correctly implemented.

**Remaining gap (V1 follow-up):** `bundle.critical.tar.gz` is never produced by `scripts/build-policies.sh`
— the `critical` target does not exist. The TTL mechanism exists but has no artifact to serve.
`scripts/build-policies.sh` must be updated to add a `critical` target that builds only
`adamance.sudo.*`, `adamance.firewall.*`, and `adamance.lib.decision`. Additionally, the YAML config field
`CriticalBundleDir` is not plumbed into `CriticalBundlePath` in the bundle server.

---

#### Policy change introduces a vulnerability that ships before review
**Required control:** Policy changes go through git → CI (rego unit tests, opa eval against fixtures) →
review (one approver minimum; two for policies touching admin groups or root access) → signed bundle build.

**As-built:** ✅ CONFIRMED. CI pipeline added in this pass.

The `release.yml` now includes a `build-policies` job (Job 0b) that runs `regal lint`, `opa test`,
`opa eval` against fixtures, `opa build` with signing, and uploads the bundle to the GitHub release.
The `release` job now depends on `build-policies`. The local `make verify-policies-bundle` target
was already present and functional.

**Finding:** TM-17 (INFO) — The CI pipeline for policy builds was not verified end-to-end in this pass.
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

**Finding:** TM-18 (RESOLVED) — `WazuhEmitter` confirmed routing to Wazuh indexer via OpenSearch bulk API. Both dev stack and the single-host package wire `WAZUH_INDEXER_URL`. StdoutEmitter fallback when not configured — no silent audit drop.

---

#### Compromised operator account changes policy
**Required control:** Sensitive operations require fresh MFA (step-up within last 5 minutes). High-impact
policy changes require a second approver via the UI.

**As-built:** ✅ CONFIRMED for MFA step-up. ❌ SECOND APPROVER NOT IMPLEMENTED.

The `authz.RequireMFA()` middleware enforces fresh MFA for sensitive endpoints. The UI has an Approvals
inbox (`web/admin-ui/src/pages/Approvals.tsx`, confirmed in M5.6 handoff). However, the backend
governance policy (`adamance.governance.require_second_approver`) does not exist, and there is no
`/api/v1/policies/publish` handler. The two-approver flow is a V1.5 feature.

**Finding:** TM-19 (MEDIUM) — The second-approver requirement for high-impact policy changes should be
verified in the OPA policy (`adamance.api.authz`) or in the handler for the policy publish endpoint.

**Resolution:** ⚠️ DOCUMENTED GAP — DEFERRED TO V1.5 (2026-05-27, go-coder-policy).

The governance policy framework (`policies/governance/`) and policy publish handler do not exist.
This is a V1.5 feature; TM-19 is not a V1 ship blocker.

---

#### Backup tampering
**Required control:** Backups signed and encrypted with a key no operator account holds. Restore requires
presenting the offline key.

**As-built:** ⚠️ RUNBOOK EXISTS, KEY MANAGEMENT NOT VERIFIED.

`docs/RUNBOOKS/restore.md` exists and references the offline backup key. The signing ceremony
(`docs/RUNBOOKS/signing-ceremony.md`) exists. The actual key storage location (USB in safe, HSM, etc.)
is an operational decision not captured in code. This is acceptable — the runbook correctly states
the requirement.

**Finding:** NONE. Operational gap, not an implementation gap.

---

#### Operator pivots from API gateway host to FreeIPA host
**Required control:** Control plane components run on separate hosts or at minimum separate user namespaces.
API gateway service account has no SSH access to other control plane hosts.

**As-built:** ⚠️ NOT VERIFIED — this is a deployment topology control.

The single-host deployment necessarily runs all control plane components on the same host. The
security architecture document acknowledges this and the multi-node topology (V1.5) is where this
control becomes meaningful. For single-host, the finding is documented.

**Finding:** TM-20 (INFO) — This control is not enforceable in the single-host topology. It applies
to HA/multi-site. The threat model should note this explicitly (single-host exemption documented).

**Resolution:** ✅ RESOLVED — single-host exemption note added (2026-05-27, red-team).

This control applies to HA/multi-site topologies only. In single-host, the operator and the control plane share the same host; this control is not enforceable. The V1 deployment guide documents this as a known limitation.

---

### Cryptographic baseline

#### TLS 1.3 only
**As-built:** ⚠️ PARTIAL CONFIRMATION.

`src/api-gateway/internal/config/config.go` TLS section was not reviewed in this pass. The design
states TLS 1.3 only. The Go `crypto/tls` library is configured via `tls.Config` in main.go. The
minimum version setting was not confirmed in this pass.

**Finding:** TM-21 (RESOLVED) — Confirmed: `src/common/mtls/tlsconfig.go` sets `MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13`. The mTLS server uses `BuildServerConfig`. TLS 1.2 is rejected. No changes required. See **TM-21** HANDOFF.

#### Internal service clients use TLS 1.2
**As-built:** ❌ VIOLATION.

The api-gateway server correctly enforces TLS 1.3 via `src/common/mtls/tlsconfig.go` (TM-21). However, multiple internal service-to-service clients still use `tls.VersionTLS12`:

| File | Line | Client |
| ---- | ---- | ------ |
| `src/api-gateway/internal/sshca/client.go` | 75 | SSH CA client |
| `src/api-gateway/internal/sshca/crl.go` | 61 | CRL fetcher |
| `src/api-gateway/internal/integrations/wazuh/client.go` | 64 | Wazuh API client |
| `src/api-gateway/internal/ipa/rpc_client.go` | 34 | FreeIPA RPC client |
| `src/api-gateway/internal/ipa/ldap_client.go` | 75, 142 | FreeIPA LDAP client |
| `src/api-gateway/cmd/server/main.go` | 341 | mTLS client (Wazuh manager) |
| `src/wazuh-bridge/internal/wazuhapi/client.go` | 65 | Wazuh API client (wazuh-bridge) |

This is a **cryptographic baseline violation**. The threat model (§ Cryptographic baseline) requires TLS 1.3 only for all internal communication.

**Finding:** TM-23 (MEDIUM) — Internal service clients use `tls.VersionTLS12` instead of `tls.VersionTLS13`. A downgrade attack or weak TLS configuration on any internal service-to-service connection could go undetected with TLS 1.2.

**Remediation:** Update all internal service clients to use `tls.VersionTLS13`. The `src/common/mtls/tlsconfig.go` `BuildClientConfig()` already enforces TLS 1.3 — all clients should use it or equivalent configuration.

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

The password hashing for user passwords in FreeIPA is handled by FreeIPA (MIT Kerberos / Dogtag). The
`configs/crypto.yaml` (referenced in SECURITY_ARCHITECTURE.md) was not reviewed in this pass. The
golang `golang.org/x/crypto/argon2` package is not directly referenced in the `src/` tree reviewed.

**Finding:** TM-22 (RESOLVED) — Audit confirms: no direct password storage in `src/api-gateway/`. All auth delegates to FreeIPA. No bcrypt, scrypt, or argon2 usage found. Compliant by design. See **TM-22** HANDOFF.

---

## Open decisions

| ID    | Decision                                             | Proposed direction                                                                                        | Owner                                     |
| ----- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| TM-01 | HA model for FreeIPA                                 | Multi-master replication across 2+ nodes; documented failover runbook                                     | SECURITY_ARCHITECTURE.md §Availability    |
| TM-02 | Where does the OPA bundle live and how is it served? | Built in CI, signed offline, served by the API gateway over mTLS, cached locally on each agent            | POLICY_MODEL.md §Distribution             |
| TM-03 | Audit log retention and immutability                 | 90 days hot in Wazuh indexer; 1 year cold in object storage with object lock                              | SECURITY_ARCHITECTURE.md §Audit           |
| TM-04 | Break-glass procedure for total directory loss       | Offline-encrypted root credentials in a sealed envelope; procedure documented (resolved). Remaining gap is only the `RUNBOOKS/` operational copy (V1_IMPLEMENTATION Phase 5). | `docs/break-glass.md` + GOVERNANCE.md §Break-glass (GOV-04) |
| TM-05 | MFA enrollment flow and recovery                     | TOTP + WebAuthn; recovery codes printed once; admin can reset MFA only with second-approver MFA challenge | SECURITY_ARCHITECTURE.md §Identity        |
| TM-06 | Rate limiting on `/oauth/token` endpoint | ✅ RESOLVED: `OAuthTokenRateLimiter` (5 req/min per IP+UA) added to `ratelimit.go`. `OAuthTokenRateLimitMiddleware` wired in `main.go`. | api-gateway |
| TM-07 | Refresh token IP + User-Agent binding | ✅ RESOLVED: `RefreshTokenStore` in `session.go` enforces IP+UA binding. Single-use. Wired into `auth.TokenHandler`. Security events emitted on IP/UA mismatch. Integration tests in `src/api-gateway/internal/handlers/auth/token_integration_test.go`. | api-gateway |
| TM-08 | Digest pinning in docker-compose.yml | ✅ RESOLVED (2026-05-27): All images in `package/adamance/docker-compose.yml` (single-host) are now digest-pinned. `freeipa/freeipa-server:rocky-9-4.12.2@sha256:e1113f67eff871768aa6d2d5929911b28f9e45fd94c8cbecd491daca01f9d40e`, `openpolicyagent/opa:latest@sha256:541f92bc1b3077453b51e3ffc7f529be188bfab56d3600c5907b3e2cb85fb33e`, `wazuh/wazuh-indexer:4.8.0@sha256:42a563f4c94bf498b87fec9b583448f8509d920dc3b39c83f8857142367ccf47`, `wazuh/wazuh-manager:4.8.0@sha256:366f142ebb28920c41bf77af1dcded832a21e9d4ed9a63741656b43639592ca2`, `wazuh/wazuh-dashboard:4.8.0@sha256:ef94e02d31262364d4ea8e1166dda1106959de602aa24d9077628b68287f6b68`. `release.yml` `digest-check` job enforces no non-digest images in CI. `scripts/pin-digests.sh` automates digest updates. | deploy |
| TM-09 | Air-gapped installer distribution path               | Document the internal package repo as a V1.5 requirement. V1 acceptable with GitHub Releases. | docs |
| TM-10 | Host keytab scope in IPA API call | ✅ RESOLVED (M7.1 + M7.3): enrollment handler scopes `host_add` and `ipa-getkeytab` to a single host principal `host/<fqdn>@REALM`. (The multi-tenant/MSP extension is descoped — single-tenant V1; see TM-25.) | api-gateway |
| TM-11 | SSH CA signing key storage and key ceremony | ✅ RESOLVED: ceremony reviewed; as-built matches docs; checklist present; prod HSM is V1.5. | security |
| TM-12 | FIM monitoring of adamance agent log paths | Confirm `ossec.conf` generated by `hostconfig/wazuh.go` includes FIM for `/var/log/adamance/`. | client-agent |
| TM-13 | Sudo command audit via Wazuh syslog/auditd | Host OS-level configuration outside adamance agent scope. Document as a host hardening prerequisite. | docs |
| TM-14 | Kerberos ticket lifetime enforcement | Verify SSSD config generated by `hostconfig/sssd.go` sets `krb5_lifetime` and per-principal `max_life`. | client-agent |
| TM-15 | OPA policies default-deny review — IN PROGRESS | Partially done: core API authz, enrollment, SSH, sudo, lib/decision reviewed. Two bugs found and fixed (see below). CIS compliance policies not yet reviewed. Remaining: firewall, fim, data, governance packages. | policies |
| TM-16 | Bundle TTL for security-critical policies | ✅ RESOLVED: `bundle.critical.tar.gz` is now built by `release.yml` (Job: build-policies) and `policies-build.yml` (main branch). Served by `bundle.go` at `/policies/bundle.critical.tar.gz` with `CriticalMaxAge=60s` (≤60s per threat model). Critical bundle sources: `policies/firewall`, `policies/lib/decision.rego` (`policies/sudo` was REMOVED — see `DESIGN_sudo_policy_via_freeipa.md`; the build now FAILS if a listed critical source is missing). Signed with K-06 key. | api-gateway + policies |
| TM-17 | CI policy build pipeline verification | ✅ RESOLVED: `build-policies` job in `release.yml` runs regal lint, `opa test`, `opa eval` fixture regression, `opa build --signature-key`. `policies-build.yml` CI also covers this. `make verify-policies-bundle` target exists. | CI |
| TM-18 | Audit log sink verification for production | ✅ RESOLVED (2026-05-27): `WazuhEmitter` in `src/common/audit/wazuh.go` sends events to Wazuh indexer via OpenSearch bulk API (`/_bulk`) when `WAZUH_INDEXER_URL` is set; falls back to stdout when not configured so no audit events are silently dropped. Both dev stack (`deploy/dev/docker-compose.dev.yml`) and the single-host production package (`package/adamance/docker-compose.yml`) wire `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS` to api-gateway. Dev stack additionally passes `WAZUH_INDEXER_CA_CERT`. | deploy |
| TM-19 | Second-approver enforcement for high-impact policy changes | ✅ BUILT — V1.5 feature delivered in Phase 6: `governance.require_second_approver.rego` in `policies/governance/`, `policy.Handler` in `src/api-gateway/internal/handlers/policy/handler.go`, approval store in `src/api-gateway/internal/storage/approval/store.go`. Routes registered in `main.go`. Graceful degradation if governance rule absent (V1 bundle). Migration: `002_policy_approvals.sql`. | api-gateway |
| TM-20 | single-host topology and the operator-pivot control | ✅ RESOLVED: single-host exemption documented in threat model. | threat model |
| TM-21 | TLS 1.3 enforcement in api-gateway Go server | ✅ RESOLVED: `src/common/mtls/tlsconfig.go` sets `MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13`. TLS 1.2 rejected. | api-gateway |
| TM-22 | Argon2id for locally-managed password hashing | ✅ RESOLVED: No direct password storage in api-gateway. All auth delegates to FreeIPA. Compliant by design. | api-gateway |
| TM-23 | Internal service clients use TLS 1.2 instead of TLS 1.3 | ✅ RESOLVED (2026-05-27): the 8 api-gateway/wazuh-bridge clients → `MinVersion: tls.VersionTLS13`. **2026-07-11 re-verification caught a residual the "no VersionTLS12 in src/" claim missed: the client-agent join bootstrap (`enroll/join.go`, 3 paths) still allowed TLS 1.2 → fixed to `tls.VersionTLS13` (commit `574dfad`). Now genuinely zero `VersionTLS12` in `src/`.** | api-gateway + wazuh-bridge + client-agent |
| TM-24 | (reserved) | | | |
| TM-25 | Tenant isolation at the FreeIPA layer (NF-1) | ⛔ **N/A for V1 — multi-tenancy was REMOVED.** adamance is single-tenant for V1 (never-MSP decision); the multi-tenant backend was deleted (`0248ebb`), so there is no per-tenant attack surface in V1. The `tenants` table is retained ONLY as the Sites FK-anchor to a single default tenant. The per-tenant Kerberos-principal isolation design (`docs/architecture/TENANT_ISOLATION.md`) is a **V2** concern and is NOT wired for V1. (Historical: it superseded the S-15 `{"TenantID": …}` option-key approach FreeIPA silently discarded.) | V2 (deferred) |
