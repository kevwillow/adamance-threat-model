# Threat Model: agent accounts

> Status: **DRAFT, written 2026-09-01** against `b276339c`, corrected and extended 2026-09-04. Owner: project maintainer.
> Companion to [`THREAT_MODEL.md`](THREAT_MODEL.md), which covers the control plane, the hosts
> and the operators. This one covers the agent principal only: a thing that holds an account here
> and is not a person.
>
> ⚠️ **Build status, said once so no row below has to repeat it.** The type fence is built and it
> fails closed. The producer is not. `mapSessionSubjectType`
> (`src/api-gateway/cmd/server/subject_extractor.go:44`) accepts the single value `"user"` and
> errors on anything else, so nothing in this tree can mint an agent session today. Every control
> below is marked BUILT, PARTIAL or DESIGNED against that. A DESIGNED row has no code behind it and
> nobody should cite it as a protection.

---

## What this document is for

An agent account is an account for something that is not a person. A coding agent on a laptop, a
scheduled job with a model behind it, an in-house script. adamance issues the account and holds the
boundary. It ships no model, calls no inference API, and has no opinion about what runs on the other
side of that boundary.

That split decides the whole document. We do not model the agent's reasoning and we are not going to
try. We assume it can be talked into anything, and we model what happens when it is.

## Scope

In scope: the agent's identity, its credentials, what it may do, what it may see, how it is
recorded, how it is rate limited, and how you kill it. The sponsor relationship. The blast radius of
an agent that has been hijacked by something it read.

Out of scope: the agent's own model, prompt, framework and supply chain. The machine it runs on,
beyond the host controls already in the main threat model.

Also out of scope, and worth saying plainly: none of this makes an agent competent. Give it a broad
grant and it will do broad damage inside that grant, quickly, and the audit trail will show you
exactly how. Scope makes mistakes small. It does not make them impossible.

## The adversary this whole subsystem exists for

### A5, hostile content reaching an obedient agent

A5 never authenticates. They do not need to. They write a ticket, a log line, a README, a comment in
a config file, a web page, and wait for your agent's task to take it there. Then they ask it for
something.

**Access:** none. **Goal:** get the agent to act for them. **Capability:** arbitrary text anywhere
the agent will read, including places nobody thinks of as an input. **Not capable of:**
authenticating, holding a certificate, or changing policy.

This is what makes an agent account different from a service account. A service account does what
its code does. An agent does what it was persuaded to do, and an agent that has been talked into
something will ask politely and mean it.

So none of the controls below are instructions in a prompt. They are checks on the same hosts that
decide whether a person may run sudo, evaluated before anything happens, enforced locally whether or
not the server is reachable. Nothing an agent reads can widen what it is allowed to do.

### A6, a compromised agent runtime

Code execution as the agent process on an enrolled host, and therefore its certificate for as long
as that certificate lives. Full use of the grant, arbitrary API calls, and tampering with anything
the local process can write.

### A7, a careless or hostile sponsor

Every agent account names a human sponsor. A sponsor who over-grants, or who is compromised
themselves, is the shortest path to a wide agent. It is in here because it is the one control with
nothing technical above it.

## Assets

| Rank | Asset | What it costs you |
| --- | --- | --- |
| 1 | The agent's short-lived certificate | Full use of the grant, on that host, until it expires |
| 2 | The sponsor's account | Re-grant, re-scope, or stand up more agents |
| 3 | What the agent can read: directory, host inventory, audit entries | Reconnaissance that outlives the credential |
| 4 | Recordings of agent runs | Whatever the agent handled, disclosed |
| 5 | Rate limit and kill switch state | An agent you cannot stop is the entire risk, restated |

## Trust boundaries

| From | To | Authentication | Status |
| --- | --- | --- | --- |
| Agent process | Local host agent, SSH | Short-lived cert bound to the enrolled host | DESIGNED |
| Agent process | API gateway | mTLS plus an agent-typed session | PARTIAL, fence built, producer absent |
| **What the agent reads** | **Agent process** | **none, and none is possible** | see A5 |
| Agent | Approval boundary | explicit refusal in policy | BUILT |

⭐ The third row is the reason this document exists. There is no authentication on what an agent
reads and there never will be. Everything else is built so that row stops mattering.

## Vectors and controls

### Privilege, and the ceiling over it

| Vector | Control | Status |
| --- | --- | --- |
| The agent is granted a privileged role, or inherits one | `SubjectTypeMayHoldPrivilege()` is a positive allowlist with one member and no escape hatch value, so a subject type nobody plumbed is refused instead of admitted. The zero value is not user (`src/api-gateway/internal/middleware/middleware.go:541`). Its policy half is `is_permitted_subject_type` in `policies/api/authz.rego`. | **BUILT** |
| The agent holds `admins` and gets treated as an admin | Refused on type before the role is ever read, so an agent carrying the `admins` group or the `admin` role still answers false (`src/api-gateway/internal/middleware/isadmin_test.go:34-35`). | **BUILT** |
| The agent approves something, including its own request | An explicit refusal, because undefined is not a rule. 🔴 Measured 2026-08-20: this used to be an assumption. Every clause of the gate required a human subject, so an agent matched no clause, the gate went undefined, and the request fell through to `default deny`. That is the same answer the policy gives for an operation nobody wired at all, which means it told you nothing. Now it is a rule with a test on it (`policies/api/authz.rego:2527`, `:2689`). | **BUILT** |
| A mistake in the rules hands an agent the keys | The ceiling does not live in the rules. Type is refused in Go and again in Rego, so a policy error on its own cannot lift it. | **BUILT** |
| The agent clears a step-up check | It holds no second factor, on purpose. The 79 step-up gated operations are closed to it because it cannot satisfy the check, not because a rule remembered to say so. | **BUILT**, inherited |

### Credentials

| Vector | Control | Status |
| --- | --- | --- |
| A long-lived token sits in a config file waiting to be copied | No password, no console sign-in, no static API token. Certificates only, shorter than a person's, issued against the identity of the enrolled machine it runs on. | **DESIGNED** |
| Someone steals the credential and uses it elsewhere | ⚠️ **Corrected 2026-09-04. This read "The certificate is bound to the host, so what they stole is worth minutes, on one box, for one scope."** A certificate carrying a hostname is not bound to that machine. If the private key can be copied, the pair works anywhere the network reaches, while still impersonating that host — which is worse than an unbound credential, because the audit trail names a box the attacker was never on. Binding needs hardware: a TPM-resident non-exportable key, or attestation the gateway actually checks. Until one of those exists the honest claim is **host-identity scoped, not host-bound**, and the bound on the damage is the certificate lifetime alone. Both halves are technically possible, so the requirement stays: keys are generated in and never leave a TPM, and the gateway refuses a certificate request that cannot attest to that. | **DESIGNED**, and weaker than it read |
| The agent's credential outlives what the sponsor is still allowed to do | ⭐ Added 2026-09-04. The grant is derived from a sponsor who can be disabled, demoted or have a group removed. Required: the agent's authority is re-derived from the sponsor's current state at decision time rather than frozen at issue time, and a sponsor's revocation propagates to every agent they sponsor inside the bound in TM-27. | **NOT MODELLED** |
| The credential outlives the agent | One action revokes the certificates, cuts live sessions, and freezes the account. | **DESIGNED** |

### What it can see, which is the control people forget

| Vector | Control | Status |
| --- | --- | --- |
| The agent enumerates your directory or your fleet | Read access is a grant like any other. No directory enumeration, no hosts outside scope, no reading anyone else's audit entries. | **DESIGNED** |
| The agent reads fleet-wide data nobody granted it | ⚠️ **Not held today.** Policy bundles are not scoped per caller, so anything that can read a bundle on an enrolled host reads every host's name, host group and SSH approval tier. An agent on that host gets it too. This contradicts the row above it, so it closes before agent accounts ship. | **OPEN, tracked** |

### Recording and attribution

| Vector | Control | Status |
| --- | --- | --- |
| Agent activity is indistinguishable from its sponsor's | `AuditActorType()` is a total mapping with no default-to-user arm, so an unrecognised type records as `ActorTypeUnattributed` and never as a human (`src/api-gateway/internal/middleware/middleware.go:561`, `src/common/audit/actor.go:29`). In a signed, hash-chained record, visibly unknown beats quietly wrong. | **BUILT** |
| The agent runs unrecorded | Recording is the condition of having an agent account, not a setting on a group. If the recorder is not live, the agent does not work. | **DESIGNED** |
| The agent tampers with its own recording | Entries are HMAC-SHA256 chained (`src/common/audit/chain.go:95`) and a signed copy leaves the box on a timer. That detects tampering, it does not prevent it. Root on the box can still destroy what is on the box. | **PARTIAL**, chain built, agent capture designed |

### Runaway behaviour

| Vector | Control | Status |
| --- | --- | --- |
| A loop goes wrong and does the same destructive thing four thousand times | Caps on actions per window and hosts touched at once. Trip a limit and the agent suspends itself rather than slowing down. | **DESIGNED** |
| The agent asks for escalation until somebody gets tired and says yes | Requests state the host, the action and the reason. Grants are windowed and expire on their own. Where dual control is on, agent requests obey it and the approver is never the requester. ⚠️ Nothing caps how often it may ask. | **PARTIAL** |
| The agent gets an approval for one thing and spends it on another | ⭐ Added 2026-09-04. A5's whole method is persuasion, so an agent that can restate a request after it was approved is the cheapest attack in this document. Required: the approval binds to the normalized operation, the target, a hash of the parameters, the policy revision in force, an expiry and a single-use nonce, and any change to those voids it. See TM-29 in the main threat model. | **NOT MODELLED** |

## What we do not defend against

- A hostile agent that you granted wide scope on purpose. The worst case for a hijacked agent is that
  it does, badly, the small set of things it was already allowed to do, on the handful of machines it
  was already scoped to, with the session on record. That is the design target. It is a statement
  about your grant, not about the agent.
- The agent's own supply chain. Model weights, framework, and the box it runs on past the host
  controls already in the main threat model.
- Prompt injection itself. We assume it works and bound what it gets.

## Still open

| ID | Item | Why it is still open |
| --- | --- | --- |
| TMA-01 | No producer | `mapSessionSubjectType` takes only `"user"`. Until something can mint an agent subject, every DESIGNED row is unexercised and every BUILT row guards a door nobody can reach. |
| TMA-02 | An open gap undercuts the read surface | An agent on an enrolled host reads fleet-wide host maps whatever its grant says. Closes before agent accounts ship. |
| TMA-03 | Rate limits and kill switch are unmeasured | Both are on the public site. No thresholds, no storage, no revocation path is written down anywhere yet. |
| TMA-04 | Approval fatigue is unbounded | Nothing limits how often an agent may ask. |
| TMA-06 | The certificate is not bound to the host | ⭐ 2026-09-04. A hostname in a certificate is a name, not a binding. Without a non-exportable key the credential is portable and impersonates a machine the attacker never touched. |
| TMA-07 | Agent approvals are not bound to what was approved | ⭐ 2026-09-04. Counting approvers is built. Binding an approval to the operation, the parameters and a nonce is not. |
| TMA-08 | Sponsor revocation does not propagate | ⭐ 2026-09-04. Nothing states how long an agent keeps working after its sponsor is disabled. |
| TMA-05 | Sponsor compromise has no control | A7 has nothing technical above it. Recorded rather than solved. |

## Where this came from

Fence tests: `src/api-gateway/internal/middleware/subjecttypefence_test.go`,
`src/api-gateway/internal/middleware/privilegepredicatefence_test.go`.
