# Threat Model: the Samba AD DC module

> Status: **DRAFT, written 2026-09-01** against `b276339c`. Owner: project maintainer.
> External review: **2026-09-26.** Read in full by three reviewers; each finding that survived checking is added or corrected in place and dated 2026-09-26, and every corrected sentence quotes what it replaced. Not a whole-document re-measure.
> Companion to [`THREAT_MODEL.md`](THREAT_MODEL.md), which has no Windows client and no Samba
> boundary in it at all. This fills that in.
>
> ⚠️ **Read the build status first, because it changes what every row below means.** The plan and
> approval machinery is built. Execution is refused on purpose: no component holds the domain
> administrator credential and none has been ruled the place to hold it, so a domain grant reaches
> the executor and is turned away by the executor's own check
> (`src/api-gateway/internal/handlers/sambaplan/executor.go:158`). The status observer is
> deliberately nil, so the screen that should report domain state answers "unknown" in every shipped
> build. Both are tracked as an open gap. Nothing here has
> ever run against a real domain controller.

---

## What this covers

Turn the optional module on and adamance stops being a thing that talks to your directory and starts
being the domain itself. Windows machines join it. That is a much larger promise than the rest of the
product makes, and it drags in an attack surface that decades of Active Directory tooling already
knows how to abuse.

The module is deliberately shaped so that almost none of it is privileged. One binary does the
irreversible work.

## The one privileged thing

`adamance-dchelper` is the only component in the build that performs an irreversible Samba forest
operation, and it runs as root. Everything about how it is written is a response to that, and it is
worth reading before judging the rest:

It never trusts the argv it is handed. Every invocation re-parses through `dctool.Parse` first, and a
malformed or hostile argv returns a refusal instead of an execution.

Every privileged invocation goes through a single `exec.Command` seam with a fixed argv. No shell, no
string-built command lines, no environment-injected paths. A test fails the build on any direct
`exec.Command` outside the sanctioned function.

The administrator password never rides on argv, because argv is world-readable through `/proc`. It is
read from stdin once, before any `samba-tool` runs, and handed to `setpassword` on stdin twice
because `setpassword` prompts twice. The fix for "argv would publish the secret" was to keep the
secret off argv rather than to redact it afterwards.

Exit codes are a contract that distinguishes "failed before anything could change" from "provisioned
and then failed", which is the distinction that decides whether a half-made domain is sitting there.

## Assets

| Rank | Asset | What it costs you |
| --- | --- | --- |
| 1 | The domain `krbtgt` secret | Forge tickets for any account in the domain, indefinitely |
| 2 | The domain administrator credential | Everything, and it is the credential that is not wired yet |
| 3 | The Samba domain database | Every account, every group, every hash |
| 4 | `SYSVOL` and `NETLOGON` | Scripts and policy that Windows clients fetch and run |
| 5 | Machine account passwords | Impersonate a joined workstation |
| 6 | Samba's DNS records | Redirect clients to a domain controller you own |
| 7 | The root helper at its fixed path | Root on the control plane, by design of the thing |

## Adversaries

**A12, a Windows client on the domain.** New here. Authenticated, ordinary, and holding a machine
account. This is the classic AD attacker position and none of the existing adversaries describe it.

**A1 and A2 as before**, now with SMB, LDAP, Kerberos and DNS reachable from wherever the domain
controller is placed.

**A4, an insider on the control plane**, who is now also a domain admin in waiting, because the box
that runs the module is the box that holds the forest.

## Trust boundaries

| From | To | Authentication | Status |
| --- | --- | --- | --- |
| Gateway | `adamance-dchelper` | Fixed-path root-owned binary, fixed argv, secret on stdin | **BUILT** |
| Windows client | Samba DC | Kerberos or NTLM, whatever the domain accepts | **NOT MODELLED** |
| Samba DC | FreeIPA | Undescribed. Two directories, one truth, and no reconciliation story | **NOT MODELLED** |
| Operator | Plan and approval | Policy, dual control where enabled | **BUILT** |
| Approved plan | The forest | Refused today, see the banner | **NOT WIRED** |

## Vectors and controls

### The helper, which is the part that is thought through

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMSAV-01 | Hostile argv reaches a root binary | Re-parsed through `dctool.Parse` on every invocation; a malformed argv is refused, not executed. | **BUILT** |
| TMSAV-02 | Shell injection through a built command line | One `exec.Command` seam, fixed argv, no shell, no env-injected paths, and a test that fails the build on any direct exec elsewhere. | **BUILT** |
| TMSAV-03 | The administrator password leaks through `/proc` | Never on argv. Read from stdin once and passed on to `setpassword` on stdin. | **BUILT** |
| TMSAV-04 | A half-provisioned domain is left behind and nobody can tell | Exit codes separate "nothing was mutated" from "provisioned, then failed". | **BUILT** |
| TMSAV-05 | An unapproved change reaches the forest | Intent, plan, approval, then execute, with the execute arm refusing today. | **BUILT** |

### The domain itself, which is not modelled at all

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMSAV-06 | Golden ticket from a stolen `krbtgt` | none ⭐ Required control, added 2026-09-26 (external review): `krbtgt` is rotated twice at provisioning, on a stated cadence, and after any suspected compromise of the domain controller, by the helper under dual control; ticket lifetimes follow the main threat model's baseline. Status read **NOT MODELLED** until 2026-09-26; no Samba configuration is tracked in the tree (`git ls-files` finds no `smb.conf`, measured at `27679898d`). | **NOT_BUILT** |
| TMSAV-07 | Pass-the-hash, pass-the-ticket, overpass-the-hash | none ⭐ Required control, added 2026-09-26 (external review): RC4 and DES are disabled for every principal, because the main threat model's Kerberos baseline applies to this KDC too. NTLM is disabled, or NTLMv2-only with the exemption recorded per client where a client cannot do without it, and machine account passwords rotate on the default 30-day cadence. Status read **NOT MODELLED** until 2026-09-26; no Samba configuration is tracked in the tree (`git ls-files` finds no `smb.conf`, measured at `27679898d`). | **NOT_BUILT** |
| TMSAV-08 | NTLM downgrade and relay to LDAP or SMB | none. Nothing records whether NTLM is disabled, whether LDAP signing and channel binding are required, or whether SMB signing is enforced. ⭐ Required control, added 2026-09-26 (external review): LDAP signing and channel binding are required, SMB signing is mandatory for server and client, SMB encryption is required, and anonymous LDAP and SMB are off. Each setting is asserted by a test over the configuration the helper renders. Status read **NOT MODELLED** until 2026-09-26; no Samba configuration is tracked in the tree (`git ls-files` finds no `smb.conf`, measured at `27679898d`). | **NOT_BUILT** |
| TMSAV-09 | DCSync, or replication abuse by a delegated account | none ⭐ Required control, added 2026-09-26 (external review): replication rights are held only by domain controller computer accounts, a grant to any other principal blocks the plan, and a DCSync attempt raises an alert. Status read **NOT MODELLED** until 2026-09-26; no Samba configuration is tracked in the tree (`git ls-files` finds no `smb.conf`, measured at `27679898d`). | **NOT_BUILT** |
| TMSAV-10 | `SYSVOL` and `NETLOGON` content that clients execute | none. Nothing describes who may write there or what integrity it has. ⭐ Required control, added 2026-09-26 (external review): `SYSVOL` and `NETLOGON` are writable only by the helper's service identity, their content is signed at publish and checked on a schedule, and a write by any other principal raises an alert. Status read **NOT MODELLED** until 2026-09-26; no Samba configuration is tracked in the tree (`git ls-files` finds no `smb.conf`, measured at `27679898d`). | **NOT_BUILT** |
| TMSAV-11 | Machine account takeover, including the well-known abuse of machine account creation quota | none ⭐ Required control, added 2026-09-26 (external review): `ms-DS-MachineAccountQuota` is 0, and machine accounts are created only through the enrolment path, with a token. Status read **NOT MODELLED** until 2026-09-26; no Samba configuration is tracked in the tree (`git ls-files` finds no `smb.conf`, measured at `27679898d`). | **NOT_BUILT** |
| TMSAV-12 | DNS poisoning against domain clients | none ⭐ Required control, added 2026-09-26 (external review): DNS dynamic updates are secure-only and limited to the record's owner, zone transfers are refused, and domain controller records are signed where clients support DNSSEC. Status read **NOT MODELLED** until 2026-09-26; no Samba configuration is tracked in the tree (`git ls-files` finds no `smb.conf`, measured at `27679898d`). | **NOT_BUILT** |
| TMSAV-13 | Exposed DC ports | Nothing specific to this module. Note that the HA compose already publishes directory ports on all interfaces, and a DC placement would compound that. ⚠️ Corrected 2026-09-26 (external review): the note that "the HA compose already publishes directory ports on all interfaces" is out of date. That publication was removed on 2026-09-05, and the HA overlay now publishes only a loopback-bound load balancer. A domain controller placement must not reintroduce it. | **NOT MODELLED** |

### Two directories, one identity

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMSAV-14 | FreeIPA and Samba disagree about who exists or what they may do | Nothing written. This is the one of most concern after the domain surface, because the product's whole pitch is one directory and one record, and this module creates a second. | **NOT MODELLED** |
| TMSAV-15 | Backup and restore restore them to different points | Nothing. Restoring one directory to an earlier state than the other is an identity inconsistency with no described resolution. | **NOT MODELLED** |
| TMSAV-16 | An account disabled in one remains usable through the other | Nothing. | **NOT MODELLED** |

## What we do not defend against

- Active Directory being Active Directory. Turning this on adopts a protocol surface with thirty
  years of known attacks, and the honest framing is that adamance runs a domain controller rather
  than that adamance makes domain controllers safe.
- Windows client hardening. We do not configure the clients.
- Anyone with root on the box that runs the module.

## Still open

| ID | Item | Why it is still open | Status |
| --- | --- | --- | --- |
| TMSA-01 | Execution is unwired | Nobody holds the administrator credential and no ruling says who should. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Still open and unchanged at HEAD 857f6f0e. `executeDomain` calls `dctoolexec.ExecuteGrant` with a literal zero `dctoolexec.Secret{}`, under a comment block stating the administrator credential is not wired and that nothing in the gateway has been ruled the place to hold it (executor.go:158-165). The refusal itself IS built and wired — a domain grant reaches the executor and is turned away by the executor's own check — so this is not missing code that someone forgot. The open gap's "what decides how long this takes" names the blocker as "a ruling on where the domain administrator credential is held", which is why the verdict is NEEDS_RULING and not NOT_BUILT. ⚠️ The callers of ExecuteGrant were not all walked to confirm no other path supplies a non-zero Secret; the executeDomain seam is the one the threat model cites. Evidence: `src/api-gateway/internal/handlers/sambaplan/executor.go:158-165` | **NEEDS_RULING** |
| TMSA-02 | Status is dark | The observer is nil in every shipped build, so operators cannot see domain state at all. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Confirmed still dark. main.go:4133 reads "⛔ Observer is deliberately nil, and that is the whole honest claim of this build" — the only Observer mentions in the whole file are that comment and :4136, with no assignment into the handler struct. The handler field carries the same admission (handler.go:200-202, "nil in every shipping configuration today") and :216 gates observation on `h.Observer != nil`, so the endpoint resolves to `unknown`. No Observer implementation exists to wire. ⚠️ handler.go:95-97 still directs the reader to `TestNoObserverIsWiredYet`, a test already recorded as never having been written — that stale citation is unfixed. Evidence: `src/api-gateway/cmd/server/main.go:4133` · `src/api-gateway/internal/handlers/sambastatus/handler.go:200-202` · `src/api-gateway/internal/handlers/sambastatus/handler.go:216` · `src/api-gateway/internal/handlers/sambastatus/handler.go:95-97` | **NOT_BUILT** |
| TMSA-03 | Never run against a real DC | The executor wants a root-owned helper at a fixed path that no CI runner provides, so the whole execute path is unexercised. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** 🔴 The row's blanket claim is FALSIFIED IN PART. `make drill-samba-destroy` (Makefile:98-99) builds the dclive test binary and runs it as root in a throwaway `--network none` Ubuntu Samba container; domain_lifecycle_live_test.go:10-18 states it is "THE ONLY THING IN THIS REPO THAT RUNS THE HELPER AGAINST A REAL samba-tool" and that it drives the production entry point Run() with argv from the production renderer dctool.Render. Five subtests run, including `provision creates a forest samba-tool accepts` (:154) and `destroy leaves no forest behind` (:212). WHAT STILL HOLDS: (a) the drill is in no CI target — it appears in neither the ci-fast nor the ci-full body; (b) its own header says it is expected to fail on the destroy half (drill-samba-destroy.sh:7), which is recorded as still failing with exit 4; (c) the GATEWAY execute path — dctoolexec invoking the installed helper at the fixed /usr/libexec path (dctoolexec/executor.go:71) — has never run against a real DC, because the TMSA-01 credential refusal stops it before it starts. ⚠️ NOT CHECKED: the drill was not run in this re-measurement; its current colour is taken from that record, not re-measured. Evidence: `Makefile:98` · `scripts/drill-samba-destroy.sh:7` · `scripts/drill-samba-destroy.sh:38-41` · `src/modules/samba/cmd/adamance-dchelper/domain_lifecycle_live_test.go:10-18` · `src/modules/samba/cmd/adamance-dchelper/domain_lifecycle_live_test.go:154` · `src/modules/samba/cmd/adamance-dchelper/domain_lifecycle_live_test.go:212` | **PARTIAL** |
| TMSA-04 | The entire Windows protocol surface | Everything in the second table above. This is the largest single unmodelled area in the product. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Confirmed absent by a 6-term concept sweep (ntlm · krbtgt · dcsync · MachineAccountQuota · server/client signing · LDAP channel binding) over the whole tree. CLASSIFYING the hits rather than counting them: in src/, policies/, deploy/ and configs/ there is not one enforcement or configuration site. The only main-tree hits are a prose comment about trust states (web/admin-ui/src/pages/Samba.tsx:17), an indirect Go module dependency (Azure/go-ntlmssp, an LDAP client library, not a DC control), and CHANGELOG/docs text. `find` for any `smb.conf*` across the tree returns NOTHING, so no Samba configuration is shipped to harden. Positive control: the same walk for `samba-tool` returns 5291 hits, so the sweep works. All eleven rows of the document's own second table (TMSAV-06 … TMSAV-13, and TMSAV-14-16) still read NOT MODELLED. The module design enumerates exactly this list — machine-account creation rights, SPN/UPN uniqueness, LDAP signing and channel binding, NTLM and RC4 policy, SMB signing, anonymous access, DNS dynamic-update ACLs, delegation, krbtgt recovery — as a version-pinned secure configuration profile still REQUIRED before shipping. That is an acknowledgment of the gap, not a model of it. ⇒ No open gap tracks the Windows protocol surface yet. Evidence: `web/admin-ui/src/pages/Samba.tsx:17` | **NOT_BUILT** |
| TMSA-05 | No FreeIPA-to-Samba reconciliation story | Two directories, and nothing says which wins or how they are kept honest. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The row's "nothing says which wins" is falsified: the design rules (✅ RULED 2026-08-08) that "authority is per object class and per mode", and its four-row table assigns FreeIPA / Samba-AD-always / Customer AD / Existing AD per object class. A later section rules equivalence unobservable and reportable as `unknown`. What remains: the reconciler PLANS and does not act — `reconcile/observed.go:4-8`, "⛔ THIS PACKAGE PLANS, IT DOES NOT ACT". ⚠️ Citation range corrected before landing: the quoted sentence about a single authority spans `:441-443`, not the `:440-442` first cited. Evidence: `src/api-gateway/internal/sambaplan/reconcile/observed.go:4` | **PARTIAL** |
| TMSA-06 | Placement is a security decision with no security write-up | Where the DC sits decides what is reachable, and the HA compose already binds directory ports widely. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** A plan with an unset firewall ruleset is mechanically blocked — but ⚠️ NOT on the citations an earlier measurement gave, and the difference matters. `BlockFirewallRulesetUnset` is raised in real code at `reconcile.go:317-322`. The two cited "call sites" in `sambaplan/handler.go` are both COMMENT lines, and the code around `:700-704` does the opposite of honouring it — on an empty ruleset digest it logs `sambaplan.observation.ruleset_refused` and CONTINUES. The blocker is actually enforced at `reconcile.go:744` (`if len(plan.Blockers) != 0 // len(plan.Refusals) != 0`) with the steps zeroed in `plan.go:215/236/258`. ⇒ The claim survives on evidence the row had not cited. Evidence: `src/api-gateway/internal/sambaplan/reconcile/reconcile.go:317` · `src/api-gateway/internal/sambaplan/reconcile/reconcile.go:744` · `src/api-gateway/internal/sambaplan/plan.go:215` ⚠️ Corrected 2026-09-26 (external review): "the HA compose already binds directory ports widely" is out of date. That was removed on 2026-09-05, and the HA overlay now publishes only a loopback-bound load balancer. | **PARTIAL** |

## Where this came from

Helper: `src/modules/samba/cmd/adamance-dchelper/doc.go`. Executor:
`src/api-gateway/internal/handlers/sambaplan/executor.go`. Status:
`src/api-gateway/internal/handlers/sambastatus/handler.go`.
