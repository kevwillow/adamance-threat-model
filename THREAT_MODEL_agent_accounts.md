# Threat Model: agent accounts

> Status: **DRAFT, written 2026-09-01** against `b276339c`, corrected and extended 2026-09-04. Owner: project maintainer.
> External review: **2026-09-26.** Read in full by three reviewers; each finding that survived checking is added or corrected in place and dated 2026-09-26, and every corrected sentence quotes what it replaced. Not a whole-document re-measure.
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
| 1 | The agent's short-lived certificate | ⚠️ **Corrected 2026-09-05. This read "Full use of the grant, on that host, until it expires."** The corrected credential row below withdrew "on that host": a certificate carrying a hostname is not bound to that machine, so a copied private key works anywhere the network reaches while still naming the enrolled host. Honest version: full use of the grant, **wherever the key is taken**, until it expires — and the audit trail names a box the holder was never on. |
| 2 | The sponsor's account | Re-grant, re-scope, or stand up more agents |
| 3 | What the agent can read: directory, host inventory, audit entries | Reconnaissance that outlives the credential |
| 4 | Recordings of agent runs | Whatever the agent handled, disclosed |
| 5 | Rate limit and kill switch state | An agent you cannot stop is the entire risk, restated |

## Trust boundaries

| From | To | Authentication | Status |
| --- | --- | --- | --- |
| Agent process | Local host agent, SSH | ⚠️ **Corrected 2026-09-05: this read "Short-lived cert bound to the enrolled host."** Short-lived cert **scoped to the enrolled host's identity, not bound to the machine.** Binding needs a TPM-resident non-exportable key or attestation the gateway checks; neither exists. See TMA-06. | DESIGNED |
| Agent process | API gateway | mTLS plus an agent-typed session | PARTIAL, fence built, producer absent |
| **What the agent reads** | **Agent process** | **none, and none is possible** | see A5 |
| Agent | Approval boundary | explicit refusal in policy | BUILT |

⭐ The third row is the reason this document exists. There is no authentication on what an agent
reads and there never will be. Everything else is built so that row stops mattering.

## Vectors and controls

### Privilege, and the ceiling over it

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMAV-01 | The agent is granted a privileged role, or inherits one | `SubjectTypeMayHoldPrivilege()` is a positive allowlist with one member and no escape hatch value, so a subject type nobody plumbed is refused instead of admitted. The zero value is not user (`src/api-gateway/internal/middleware/middleware.go:541`). Its policy half is `is_permitted_subject_type` in `policies/api/authz.rego`. | **BUILT** |
| TMAV-02 | The agent holds `admins` and gets treated as an admin | Refused on type before the role is ever read, so an agent carrying the `admins` group or the `admin` role still answers false (`src/api-gateway/internal/middleware/isadmin_test.go:34-35`). | **BUILT** |
| TMAV-03 | The agent approves something, including its own request | An explicit refusal, because undefined is not a rule. 🔴 Measured 2026-08-20: this used to be an assumption. Every clause of the gate required a human subject, so an agent matched no clause, the gate went undefined, and the request fell through to `default deny`. That is the same answer the policy gives for an operation nobody wired at all, which means it told you nothing. Now it is a rule with a test on it (`policies/api/authz.rego:2527`, `:2689`). | **BUILT** |
| TMAV-04 | A mistake in the rules hands an agent the keys | The ceiling does not live in the rules. Type is refused in Go and again in Rego, so a policy error on its own cannot lift it. | **BUILT** |
| TMAV-05 | The agent clears a step-up check | It holds no second factor, on purpose. The 79 step-up gated operations are closed to it because it cannot satisfy the check, not because a rule remembered to say so. ⭐ Measured 2026-09-26 at `27679898d` (an external review raised it): the refusal does not depend on the deployment's second-factor opt-out. `check_user_with_mfa_stepup` refuses any subject that is not a human user before the opt-out is consulted (`policies/api/authz.rego:2601`), and both opt-out clauses require `is_human_user_subject` (`:2670`, `:2702`). A guard that takes the opt-out and presents an agent subject is owed. | **BUILT**, inherited |

### Credentials

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMAV-06 | A long-lived token sits in a config file waiting to be copied | No password, no console sign-in, no static API token. Certificates only, shorter than a person's, issued against the identity of the enrolled machine it runs on. | **DESIGNED** |
| TMAV-07 | Someone steals the credential and uses it elsewhere | ⚠️ **Corrected 2026-09-04. This read "The certificate is bound to the host, so what they stole is worth minutes, on one box, for one scope."** A certificate carrying a hostname is not bound to that machine. If the private key can be copied, the pair works anywhere the network reaches, while still impersonating that host — which is worse than an unbound credential, because the audit trail names a box the attacker was never on. Binding needs hardware: a TPM-resident non-exportable key, or attestation the gateway actually checks. Until one of those exists the honest claim is **host-identity scoped, not host-bound**, and the bound on the damage is the certificate lifetime alone. Both halves are technically possible, so the requirement stays: keys are generated in and never leave a TPM, and the gateway refuses a certificate request that cannot attest to that. | **DESIGNED**, and weaker than it read |
| TMAV-08 | The agent's credential outlives what the sponsor is still allowed to do | ⭐ Added 2026-09-04. The grant is derived from a sponsor who can be disabled, demoted or have a group removed. Required: the agent's authority is re-derived from the sponsor's current state at decision time rather than frozen at issue time, and a sponsor's revocation propagates to every agent they sponsor inside the bound in TM-27. | **NOT MODELLED** |
| TMAV-09 | The credential outlives the agent | One action revokes the certificates, cuts live sessions, and freezes the account. | **DESIGNED** |
| TMAV-18 | An agent acts through its sponsor's human credential instead of its own | ⭐ Added 2026-09-26 (external review). The type fence holds only if the agent uses the agent credential. An agent's execution environment can neither read nor invoke human session tokens, Kerberos caches, SSH agents, browser stores or human signing services. Agent credentials are reachable only through an OS identity or credential broker that preserves the agent subject type, and a TPM-resident key also has a process-authorisation boundary: being able to call its signing interface counts as using the credential. Delegated actions keep the agent identity and the sponsor link rather than minting an ordinary human session. | **NOT MEASURED** |

### What it can see, which is the control people forget

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMAV-10 | The agent enumerates your directory or your fleet | Read access is a grant like any other. No directory enumeration, no hosts outside scope, no reading anyone else's audit entries. | **DESIGNED** |
| TMAV-11 | The agent reads fleet-wide data nobody granted it | ⚠️ **Not held today.** Policy bundles are not scoped per caller, so anything that can read a bundle on an enrolled host reads every host's name, host group and SSH approval tier. An agent on that host gets it too. This contradicts the row above it, so it closes before agent accounts ship. | **OPEN, tracked** |

### Recording and attribution

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMAV-12 | Agent activity is indistinguishable from its sponsor's | `AuditActorType()` is a total mapping with no default-to-user arm, so an unrecognised type records as `ActorTypeUnattributed` and never as a human (`src/api-gateway/internal/middleware/middleware.go:561`, `src/common/audit/actor.go:29`). In a signed, hash-chained record, visibly unknown beats quietly wrong. | **BUILT** |
| TMAV-13 | The agent runs unrecorded | Recording is the condition of having an agent account, not a setting on a group. If the recorder is not live, the agent does not work. | **DESIGNED** |
| TMAV-14 | The agent tampers with its own recording | Entries are HMAC-SHA256 chained (`src/common/audit/chain.go:95`). That detects tampering, it does not prevent it. Root on the box can still destroy what is on the box. ⚠️ **Corrected 2026-09-05: this row also said "and a signed copy leaves the box on a timer", which republished a control the anchoring model has since withdrawn twice over.** Nothing signed in any independently checkable sense leaves the box — the anchor is HMAC'd under the chain's own key — and the only sink that exists today is a Wazuh instance inside this same stack. See TMA2-07 and TMA2-11. | **PARTIAL**, chain built, agent capture designed, off-box copy not built |

### Runaway behaviour

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMAV-15 | A loop goes wrong and does the same destructive thing four thousand times | Caps on actions per window and hosts touched at once. Trip a limit and the agent suspends itself rather than slowing down. | **DESIGNED** |
| TMAV-16 | The agent asks for escalation until somebody gets tired and says yes | Requests state the host, the action and the reason. Grants are windowed and expire on their own. Where dual control is on, agent requests obey it and the approver is never the requester. ⚠️ Nothing caps how often it may ask. | **PARTIAL** |
| TMAV-17 | The agent gets an approval for one thing and spends it on another | ⭐ Added 2026-09-04. A5's whole method is persuasion, so an agent that can restate a request after it was approved is the cheapest attack in this document. Required: the approval binds to the normalized operation, the target, a hash of the parameters, the policy revision in force, an expiry and a single-use nonce, and any change to those voids it. ⚠️ Measured 2026-09-04: `approval.Approval` (`src/api-gateway/internal/storage/approval/store.go:92`) carries `ChangeScope`, `BundleDigest` and `ExpiresAt`, so the policy-publish path already binds to the content it approved; there is no nonce, no policy revision and no parameter hash for any other operation. See TM-29 in the main threat model. | **PARTIAL** |

## What we do not defend against

- A hostile agent that you granted wide scope on purpose. The worst case for a hijacked agent is that
  it does, badly, the small set of things it was already allowed to do, on the handful of machines it
  was already scoped to, with the session on record. That is the design target. It is a statement
  about your grant, not about the agent.
- The agent's own supply chain. Model weights, framework, and the box it runs on past the host
  controls already in the main threat model.
- Prompt injection itself. We assume it works and bound what it gets.

## Still open

| ID | Item | Why it is still open | Status |
| --- | --- | --- | --- |
| TMA-01 | No producer | `mapSessionSubjectType` takes only `"user"`. Until something can mint an agent subject, every DESIGNED row is unexercised and every BUILT row guards a door nobody can reach. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The refusal is built and the producer is not. `mapSessionSubjectType` (`subject_extractor.go:44-54`) has exactly one arm — `SubjectTypeUser` — and a refusing default; `mintvalues.go:39-44` states that user "is the only subject type a SESSION token may carry" and `:137` hardcodes it. `SubjectTypeAgent` exists (`middleware.go:410`) with an audit-actor mapping at `:570`, but of 17 tree-wide references only FOUR are non-test. ⇒ the agent subject type is a FENCE, not a producer: nothing can mint one. ⚠️ Owning gap corrected before landing — an earlier measurement named the "Nothing in the tree ever reads an Active Directory group" row, which is unrelated. Evidence: `src/api-gateway/internal/middleware/subject_extractor.go:44` · `src/api-gateway/internal/session/mintvalues.go:39` · `src/api-gateway/internal/session/mintvalues.go:137` · `src/api-gateway/internal/middleware/middleware.go:410` Tracked as an open gap: the refusal to let an AI agent hold an account is fully built; what is missing is the minting half. | **NOT_BUILT** |
| TMA-02 | An open gap undercuts the read surface | An agent on an enrolled host reads fleet-wide host maps whatever its grant says. Closes before agent accounts ship. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Per-caller bundle scoping does not exist. bundle.go:396 still selects with `switch path.Base(r.URL.Path)`, whose three arms choose bundle KIND (critical / compliance / operational) and never the caller, so every admitted host receives byte-identical bytes. It is still open. ONE CHANGE SINCE IT WAS WRITTEN, classified rather than reported as a count: its evidence line `grep -c HostIdentityFromContext bundle.go -> 0` is now stale — bundle.go:862 reads it inside admit(), which refuses any caller that is not both certificate-verified and currently enrolled, with every refusal reason collapsed to one caller-visible answer to avoid an enrolment oracle. That is an ADMISSION gate, not a SCOPING one; it changes who gets a bundle, not what the bundle says. The row's substance holds. Evidence: `src/api-gateway/internal/bundle/bundle.go:396-420` · `src/api-gateway/internal/bundle/bundle.go:845-871` | **NOT_BUILT** |
| TMA-03 | Rate limits and kill switch are unmeasured | Both are on the public site. No thresholds, no storage, no revocation path is written down anywhere yet. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Nothing is built, but the row's own reason is HALF STALE and should be corrected. The kill switch IS written down now: the agent-grants design rules it (cut off at the next request to the typeless floor, plus revoke live sessions via the account reaper's existing path), and names the storage — Suspended bool, SuspendedAt, SuspendedBy, checked FIRST ahead of mode, hatches and profile. So 'no storage, no revocation path is written down anywhere' is refuted for that half. NONE OF IT IS IN THE TREE: `grep -rn 'Suspended' --include='*.go' src/ / grep -v _test` returns zero hits, and src/api-gateway/internal/storage/ has 33 stores, none for agent grants. The rate-limit half is written down nowhere: I classified every rate-limit site rather than counting them — middleware/ratelimit.go:280-299 limits certificate-sign requests per authenticated principal, IPRateLimitMiddleware limits per source IP, and the others are join, recordings-ingest and notification-stream limiters. None caps an agent's actions per window or hosts touched at once, and none self-suspends. The client-agent's own run.go:19-21 states the run ID is explicitly NOT a kill switch. Evidence: `src/client-agent/internal/agentrun/run.go:19-21` · `src/api-gateway/internal/middleware/ratelimit.go:280-299` | **NOT_BUILT** |
| TMA-04 | Approval fatigue is unbounded | Nothing limits how often an agent may ask. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Nothing bounds how often an approval may be requested, by an agent or by anyone. policies/governance/require_approval.rego decides purely by counting distinct approvers against a required count and excluding the requester (:208-215 approve, :234-243 refuse-with-more-needed); there is no clause about request frequency, no cooldown and no per-requester budget. A concept search with six terms (ratelimit, rate limit, too many, fatigue, cooldown, backoff) over handlers/approvals/, handlers/jit/ and storage/approval/ returned zero non-test hits, and the same terms against policies/ returned zero. Moot in practice today because no agent subject can be minted to ask (TMA-01), but the control is absent for human requesters too. Evidence: `policies/governance/require_approval.rego:208-215` · `policies/governance/require_approval.rego:234-243` | **NOT_BUILT** |
| TMA-05 | Sponsor compromise has no control | A7 has nothing technical above it. Recorded rather than solved. ⚠️ **Reordered 2026-09-05: this row printed after TMA-08, the same defect the anchoring model's TMA2-05 had, and has been moved back into sequence.** ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** There is no agent sponsor relationship in code, so there is nothing for a control to sit above. I classified the 471 tree-wide `sponsor` hits rather than reporting the count: every one belongs to the GUEST/household account sponsor from the account-types design — the account_profile.sponsor_subject_uuid / sponsor_uid columns, migration 0077_account_sponsor.sql, and the departure path. None concerns an agent, and an open gap records that there is no agent account kind at all (account_type CHECK admits regular, admin, household, guest). The nearest built machinery is departure.go's SponsorRelation (:37-40) calling ClearSponsorBySponsor (:117-123), wired at main.go:3705-3720 — but that unsponsors a departing sponsor's guests, it does not constrain what a sponsor may grant. CAVEAT, which is why this is inferred: compensating controls that might bound a sponsor in general were not exhaustively enumerated (dual control on grant issuance, operator scope, the approval matrix). ALSO NOTE the vocabulary question — the row's phrase 'recorded rather than solved' reads like an acceptance, but it sits in the Still-open table and no ruling records a decision not to build it, so ACCEPTED would be wrong. Evidence: `src/api-gateway/internal/handlers/users/departure.go:37-40` · `src/api-gateway/internal/handlers/users/departure.go:117-123` · `src/api-gateway/cmd/server/main.go:3705-3720` | **NOT_BUILT** |
| TMA-06 | The certificate is not bound to the host | ⭐ 2026-09-04. A hostname in a certificate is a name, not a binding. Without a non-exportable key the credential is portable and impersonates a machine the attacker never touched. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The requirement TMAV-07 states — keys generated in and never leaving a TPM, and a gateway that refuses a certificate request which cannot attest to that — is met nowhere. The agent's mTLS private key is generated in software: rsa.GenerateKey(rand.Reader, 2048) at enroll.go:231 for the enrolment CSR and again at certrenew.go:262 at every renewal, both confirmed by an earlier measurement at db63ea4d. I searched the TPM concept with five terms (tpm, tpm2, swtpm, non-exportable, attestation) across src/, policies/, deploy/ and scripts/ and CLASSIFIED every hit: they are all either OpenBao unseal-share custody (deploy/setup/openbao-init.sh:128-138 seals a data key to the chip, vaultcustody/classify.go:15 PostureTPM, opshealth, deploy/setup/lib/compose.sh:9) or OpenBao Transit non-exportable SIGNING keys (policysign/signer.go:8, handlers/policy/handler.go:180). Not one concerns an agent client certificate, and no gateway path checks any attestation at issuance or renewal. A hostname in the certificate remains a name, exactly as the corrected TMAV-07 says. Evidence: `src/client-agent/internal/enroll/enroll.go:231` · `src/client-agent/internal/certrenew/certrenew.go:262` · `deploy/setup/openbao-init.sh:128-138` · `src/api-gateway/internal/vaultcustody/classify.go:15` | **NOT_BUILT** |
| TMA-07 | Agent approvals are not bound to what was approved | ⭐ 2026-09-04. Counting approvers is built, and the policy-publish path binds a `BundleDigest`. Binding a general approval to the operation, the target, the parameters, the policy revision and a single-use nonce is not. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Fourteen of twenty approval bindings are field-bound (re-measured). ⚠️ Two residuals an earlier measurement listed are REFUTED from code and are struck here: `user.create` DOES bind every field it applies — `handler.go:1786-1787` canonicalises uid, givenname, sn, mail, password (SHA-256'd at `:1783`) and groups; and `sshca.cert_sign` DOES bind the public key — `sign.go:861-862` includes `pubkey=%s` from a fingerprint computed at `:856-860`. What genuinely remains: approvals are NOT single-use — a search for `nonce` across the governance rego and the approval store returns zero hits — and the rego arms at `:208-215` and `:234-243` count approvers without binding the payload. Evidence: `src/api-gateway/internal/handlers/users/handler.go:1786` · `src/api-gateway/internal/handlers/sshca/sign.go:861` · `policies/api/authz.rego:208` | **PARTIAL** |
| TMA-08 | Sponsor revocation does not propagate | ⭐ 2026-09-04. Nothing states how long an agent keeps working after its sponsor is disabled. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Nothing re-derives an agent's authority from its sponsor's current state, because neither the agent principal nor the agent-sponsor link exists (TMA-01, TMA-05). The general defect the row points at is owned by the revocation-convergence gap: twelve revocable things each carry their own TTL configured in its own place, no document adds them up, and nobody can answer how long a disabled account keeps working or on which paths — the bundle and KRL poll loops both default to a literal 60, sixty seconds and sixty minutes respectively. The nearest built analogue is the guest path: departure.go's header ruling (:29-34) states that a DISABLE clears sponsorship as well as a delete, and ClearSponsorBySponsor is called at :117-123. That is an unsponsoring of dependent guest accounts surfaced for an operator to act on — it is not authority re-derivation at decision time, it carries no stated propagation bound, and it does not touch agents. Evidence: `src/api-gateway/internal/handlers/users/departure.go:29-34` · `src/api-gateway/internal/handlers/users/departure.go:117-123` | **NOT_BUILT** |

## Where this came from

Fence tests: `src/api-gateway/internal/middleware/subjecttypefence_test.go`,
`src/api-gateway/internal/middleware/privilegepredicatefence_test.go`.
