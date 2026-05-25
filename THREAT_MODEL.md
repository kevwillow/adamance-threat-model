# Threat Model: linux-ad

> Status: **DRAFT** — initial pass for review. Owner: security architecture. Last reviewed: 2026-05-24.

## Purpose

This document defines **what linux-ad defends against and why.** Every security decision elsewhere in the project should
trace back to a threat described here. If a control doesn't address a documented threat, it's probably ceremony. If a
threat has no control, it's a gap and must be tracked.

This is the source of truth for security requirements. Anything in `docker-compose.yml`, the API code, the client agent,
or the UI that contradicts this document is a bug.

## Scope

**In scope:**

- The linux-ad control plane (FreeIPA, OPA, Wazuh, API gateway, admin UI)
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

| From                          | To                          | Boundary type              | Authentication                    | Channel                 |
| ----------------------------- | --------------------------- | -------------------------- | --------------------------------- | ----------------------- |
| User browser                  | Reverse proxy / UI          | Public ↔ edge              | TLS server cert                   | TLS 1.3                 |
| Admin UI                      | API gateway                 | Edge ↔ control plane       | OIDC bearer JWT + CSRF token      | TLS 1.3                 |
| API gateway                   | FreeIPA                     | Intra-control-plane        | Service principal + GSSAPI        | LDAPS / Kerberos        |
| API gateway                   | OPA                         | Intra-control-plane        | mTLS (SPIFFE-style SVIDs)         | HTTPS                   |
| API gateway                   | Wazuh API                   | Intra-control-plane        | mTLS + scoped API key             | HTTPS                   |
| API gateway                   | Postgres                    | Intra-control-plane        | DB credential (Vault-issued)      | TLS (local socket in T1) |
| Managed host (SSSD)           | FreeIPA                     | Untrusted ↔ control plane  | Host keytab                       | Kerberos / LDAPS        |
| Managed host (Wazuh agent)    | Wazuh manager               | Untrusted ↔ control plane  | Pre-shared agent key, mutual auth | Wazuh proto (encrypted) |
| Managed host (linux-ad agent) | OPA bundle endpoint         | Untrusted ↔ control plane  | Signed bundles + mTLS host cert   | HTTPS                   |
| Operator workstation          | Control plane (break-glass) | Privileged ↔ control plane | Hardware token + audited bastion  | SSH over WireGuard      |

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
- Password hashing inside any linux-ad-owned component: Argon2id with parameters reviewed annually.
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

## Open decisions

Tracked here until resolved; each links to a follow-up doc when written.

| ID    | Decision                                             | Proposed direction                                                                                        | Owner                                     |
| ----- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| TM-01 | HA model for FreeIPA                                 | Multi-master replication across 2+ nodes; documented failover runbook                                     | SECURITY_ARCHITECTURE.md §Availability    |
| TM-02 | Where does the OPA bundle live and how is it served? | Built in CI, signed offline, served by the API gateway over mTLS, cached locally on each agent            | POLICY_MODEL.md §Distribution             |
| TM-03 | Audit log retention and immutability                 | 90 days hot in Wazuh indexer; 1 year cold in object storage with object lock                              | SECURITY_ARCHITECTURE.md §Audit           |
| TM-04 | Break-glass procedure for total directory loss       | Offline-encrypted root credentials in a sealed envelope; procedure documented (resolved). Remaining gap is only the `RUNBOOKS/` operational copy (V1_IMPLEMENTATION Phase 5). | `docs/break-glass.md` + GOVERNANCE.md §Break-glass (GOV-04) |
| TM-05 | MFA enrollment flow and recovery                     | TOTP + WebAuthn; recovery codes printed once; admin can reset MFA only with second-approver MFA challenge | SECURITY_ARCHITECTURE.md §Identity        |

## Revision history

| Date       | Change        | Author |
| ---------- | ------------- | ------ |
| 2026-05-24 | Initial draft | —      |
