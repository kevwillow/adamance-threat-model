# Threat Model: the Samba AD DC module

> Status: **DRAFT, first pass, written 2026-09-01** against `b276339c`. Owner: project maintainer.
> Companion to [`docs/THREAT_MODEL.md`](THREAT_MODEL.md), which has no Windows client and no Samba
> boundary in it at all. This fills that in.
>
> ⚠️ **Read the build status first, because it changes what every row below means.** The plan and
> approval machinery is built. Execution is refused on purpose: no component holds the domain
> administrator credential and none has been ruled the place to hold it, so a domain grant reaches
> the executor and is turned away by the executor's own check
> (`src/api-gateway/internal/handlers/sambaplan/executor.go:158`). The status observer is
> deliberately nil, so the screen that should report domain state answers "unknown" in every shipped
> build. Both are tracked as G07 in [`docs/V1_GAP_REGISTRY.md`](V1_GAP_REGISTRY.md). Nothing here has
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

| Vector | Control | Status |
| --- | --- | --- |
| Hostile argv reaches a root binary | Re-parsed through `dctool.Parse` on every invocation; a malformed argv is refused, not executed. | **BUILT** |
| Shell injection through a built command line | One `exec.Command` seam, fixed argv, no shell, no env-injected paths, and a test that fails the build on any direct exec elsewhere. | **BUILT** |
| The administrator password leaks through `/proc` | Never on argv. Read from stdin once and passed on to `setpassword` on stdin. | **BUILT** |
| A half-provisioned domain is left behind and nobody can tell | Exit codes separate "nothing was mutated" from "provisioned, then failed". | **BUILT** |
| An unapproved change reaches the forest | Intent, plan, approval, then execute, with the execute arm refusing today. | **BUILT** |

### The domain itself, which is not modelled at all

| Vector | Control | Status |
| --- | --- | --- |
| Golden ticket from a stolen `krbtgt` | none | **NOT MODELLED** |
| Pass-the-hash, pass-the-ticket, overpass-the-hash | none | **NOT MODELLED** |
| NTLM downgrade and relay to LDAP or SMB | none. Nothing records whether NTLM is disabled, whether LDAP signing and channel binding are required, or whether SMB signing is enforced. | **NOT MODELLED** |
| DCSync, or replication abuse by a delegated account | none | **NOT MODELLED** |
| `SYSVOL` and `NETLOGON` content that clients execute | none. Nothing describes who may write there or what integrity it has. | **NOT MODELLED** |
| Machine account takeover, including the well-known abuse of machine account creation quota | none | **NOT MODELLED** |
| DNS poisoning against domain clients | none | **NOT MODELLED** |
| Exposed DC ports | Nothing specific to this module. Note G85: the HA compose already publishes directory ports on all interfaces, and a DC placement would compound that. | **NOT MODELLED** |

### Two directories, one identity

| Vector | Control | Status |
| --- | --- | --- |
| FreeIPA and Samba disagree about who exists or what they may do | Nothing written. This is the one I would worry about most after the domain surface, because the product's whole pitch is one directory and one record, and this module creates a second. | **NOT MODELLED** |
| Backup and restore restore them to different points | Nothing. Restoring one directory to an earlier state than the other is an identity inconsistency with no described resolution. | **NOT MODELLED** |
| An account disabled in one remains usable through the other | Nothing. | **NOT MODELLED** |

## What we do not defend against

- Active Directory being Active Directory. Turning this on adopts a protocol surface with thirty
  years of known attacks, and the honest framing is that adamance runs a domain controller rather
  than that adamance makes domain controllers safe.
- Windows client hardening. We do not configure the clients.
- Anyone with root on the box that runs the module.

## Still open

| ID | Item | Why it is still open |
| --- | --- | --- |
| TMSA-01 | Execution is unwired | Nobody holds the administrator credential and no ruling says who should. G07. |
| TMSA-02 | Status is dark | The observer is nil in every shipped build, so operators cannot see domain state at all. G07. |
| TMSA-03 | Never run against a real DC | The executor wants a root-owned helper at a fixed path that no CI runner provides, so the whole execute path is unexercised. |
| TMSA-04 | The entire Windows protocol surface | Everything in the second table above. This is the largest single unmodelled area in the product. |
| TMSA-05 | No FreeIPA-to-Samba reconciliation story | Two directories, and nothing says which wins or how they are kept honest. |
| TMSA-06 | Placement is a security decision with no security write-up | Where the DC sits decides what is reachable, and G85 shows the HA compose already binds directory ports widely. |

## Where this came from

[`docs/DESIGN_samba_ad_dc.md`](DESIGN_samba_ad_dc.md),
[`docs/DESIGN_samba_mode_b.md`](DESIGN_samba_mode_b.md),
[`docs/DESIGN_samba_b1_placement.md`](DESIGN_samba_b1_placement.md),
[`docs/DESIGN_samba_b2_producer.md`](DESIGN_samba_b2_producer.md),
[`docs/DESIGN_samba_plan_approval.md`](DESIGN_samba_plan_approval.md).
Helper: `src/modules/samba/cmd/adamance-dchelper/doc.go`. Executor:
`src/api-gateway/internal/handlers/sambaplan/executor.go`. Status:
`src/api-gateway/internal/handlers/sambastatus/handler.go`.
