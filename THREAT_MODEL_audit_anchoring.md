# Threat Model: the audit chain and its off-box copy

> Status: **DRAFT, written 2026-09-01** against `b276339c`, corrected and extended 2026-09-04,
> and again 2026-09-05. Owner: project maintainer.
>
> ⚖️ **The 2026-09-05 pass reversed a ruling the 2026-09-04 pass had made.** Preservation was
> promoted to the primary control and then demoted again: completeness, provenance and
> preservation are conjunctive and none of them dominates. Both wordings are on the TMA2-06 row,
> the withdrawn one quoted. Four rows were added (TMA2-10 to TMA2-13), and the reason they are
> worth reading is that each describes a way the subsystem fails while every check it currently
> performs still passes.
>
> Companion to [`THREAT_MODEL.md`](THREAT_MODEL.md), which covers who may do what. This one
> covers whether you can still prove it afterwards.

---

## What this is for

The audit chain is the thing that survives the attack. Every other control here is about stopping
something. This one is about the morning after, when the question is what happened and whether the
record of it can be trusted.

Two properties, and they are not the same:

**Tamper-evident.** You can prove entries were altered, inserted, deleted or reordered. Built.

**Tamper-resistant.** The attacker cannot do it in the first place. Not built, and not achievable on
a box they own. Root on the machine can destroy what is on the machine. The design accepts that and
puts a copy somewhere else instead.

Everything below follows from taking that second sentence seriously.

## How it works today

Every entry carries a sequence number, the hash of the entry before it, and an HMAC-SHA256 computed
over that sequence number, that previous hash, and the canonical form of the event
(`src/common/audit/chain.go:95`). Alter one field and every hash after it stops matching.

A hash chain on its own only proves internal consistency. Someone who holds the key can rewrite the
whole thing from any point and re-chain it, and the result verifies. What defeats that is an
**anchor**: a periodic record of the head sequence and head hash, published somewhere the attacker
does not control, so a rewritten chain disagrees with a copy that left the building
(`src/api-gateway/internal/storage/auditchain/store.go:512`).

The compliance side is wired to that rather than to an operator's word. `audit_tamper_protection_enabled`
is true only when the HMAC key is configured, the chain verifies intact, and the anchor is live. A
broken chain flips the control to failing. That is the difference between asserting compliance and
demonstrating it, and it is the part of this subsystem I am most confident in.

## Where the copy goes, and whose problem it is

Four destinations, all in v1. A signed copy of the chain head leaves the box on a timer to any of
them:

**A git repository.** The anchor chain becomes a commit history, which is content-addressed and
cheap to hold somewhere else. Recommended first because it costs nothing.

**An email account.** A mailbox is an append-only log that somebody else timestamps for you.

**Any machine you can reach, over SSH or SCP.** A NAS, a spare box in the cupboard, whatever you
already run.

**Object storage you control**, including write-once WORM hardware, where object locking means what
lands there cannot be rewritten, including by you.

### The boundary, stated once and applied to every row below

⭐ **The destination account is yours to secure.** adamance signs what it sends, records what it sent
and when, and notices when the witness goes stale. It does not run your git host, your mailbox or the
box in your cupboard, and it does not defend them. If someone owns your git account, they own the
copy you put there.

That is a boundary, not a gap, and it is the same one every backup product draws. It also means the
useful advice is to pick a destination whose account is not the one an attacker gets on the way to
your control plane. A mailbox you sign into from the same laptop as the console is a weaker choice
than a git account with its own key, and neither is as strong as a locked object store.

⚠️ **Build status.** The four destinations are v1 scope and are being built now, alongside the setup
prompt described below. The sink model in the tree today has one value, `anchorSinkWazuh = "wazuh"`
(`src/api-gateway/cmd/server/main.go:5984`), so treat every destination row below as the shape v1
ships rather than as something you can point at in the current build. Tracked as an open gap.

### Setting one up

Install, or first admin setup, prompts for a destination and says it is recommended. It is a
recommendation and not a gate: adamance runs without one, and a small deployment that never wires a
destination gets a chain that is self-verifying and nothing more. Which is worth knowing, because a
chain with no external witness catches a clumsy edit and not a competent one.

## Assets

| Rank | Asset | What it costs you |
| --- | --- | --- |
| 1 | The HMAC chain key | Rewrite history from any point and re-chain it, and every check passes |
| 1= | The anchor signing key | ⭐ Added 2026-09-04. Anchors are described throughout this document as signed and this key was in no asset list. Forge an anchor and the one witness that catches a rewritten chain agrees with the rewrite, which collapses row 1 and this row into a single compromise. 🔴 **Measured 2026-09-04: it is the HMAC chain key, so anyone who can verify an anchor can forge one.** ⚠️ **Corrected 2026-09-05. That sentence used to continue "and the subsystem is worth nothing against A4", and that was too strong to be true.** An anchor that has ALREADY REACHED a destination the control plane cannot rewrite is beyond the reach of somebody who takes the key afterwards. Holding the key buys a *conflicting* history, not the erasure of the one already sent — and a conflict is itself evidence, provided the verifier reads every anchor it has rather than only the newest, and the destination genuinely cannot be rewritten. What the symmetric key actually costs is narrower and still serious: verification cannot be handed to anyone without handing them forgery along with it, and a private half that lives on the control plane does not escape A4 whatever algorithm signs with it. ⚠️ **Corrected 2026-09-05, second pass. This row read "⇒ The dominant control here is the DESTINATION, not the key. See TMA2-06, which is the answer this row was reaching for." That ranking was withdrawn by TMA2-06's own correction later the same day, and this sentence outlived the ruling it pointed at.** The destination is not dominant either. Under the chain's own symmetric key a preserved stream is bytes that agree with themselves, so a destination the control plane genuinely cannot rewrite still holds a history the key-holder may have fabricated before it was sent. ⇒ **Completeness, provenance and preservation are CONJUNCTIVE. None dominates.** See TMA2-06. There is no separate anchor signing key. `WriteAnchor` (`src/api-gateway/internal/storage/auditchain/store.go:512`) stores the chain's own `key_id`, and the off-box copy is `emitAuditChainAnchor`'s `iam.audit.chain_anchor` event (`src/api-gateway/cmd/server/main.go:7253`) routed back through the same `ChainEmitter`. See TMA2-07. |
| 2 | The anchor records | Without them the chain only proves it agrees with itself |
| 3 | Credentials for the off-box destination | Reach the one copy the attacker is not supposed to own |
| 4 | The audit database | Destroy or truncate the record locally |
| 5 | Contents of the audit entries | Whatever your people and agents were doing, disclosed |

## Adversaries

**A2, a compromised host.** Can tamper with its own local logs. Bounded, because the chain lives on
the control plane and not on the host.

**A4, an insider on the control plane.** The one this is written for. Holds the database, probably
holds the key, and wants the record of what they did to be gone or plausible.

**A10, whoever holds the off-box destination.** New here, and answered by the boundary above rather
than by a control. Ship a signed copy to a git host or a mailbox and the security of that copy is the
security of that account, which is yours. We model what adamance owes you, which is a signed copy, an
honest record of what was sent, and a loud complaint when the witness goes stale. We do not model
your mailbox.

## Trust boundaries

| From | To | Authentication | Status |
| --- | --- | --- | --- |
| Gateway | Audit database | DB credential | **BUILT** |
| Gateway | Git, mail, SSH or SCP, object storage | Credentials for an account you own | **V1, BUILDING** |
| Gateway | Wazuh indexer, where the module is on | Indexer credentials | **BUILT** |
| **You** | **The destination account** | **yours, and outside our boundary** | **STATED, see above** |
| Anyone verifying | An anchor copy | The anchor is the witness, so its integrity is the whole point | **PARTIAL** |

## Vectors and controls

### Against the chain itself

| Vector | Control | Status |
| --- | --- | --- |
| Edit one entry in place | Chained HMAC-SHA256, so every subsequent hash stops matching (`src/common/audit/chain.go:95`). | **BUILT** |
| Delete or reorder entries | Sequence numbers and previous-hash linkage, checked by `Store.Check` and `Store.Intact`. | **BUILT** |
| Truncate the tail, which is the quiet one | The anchor holds a head sequence higher than the surviving chain, and `anchorBreak` reports the disagreement (`src/api-gateway/internal/storage/auditchain/store.go:468`). Without an anchor, a clean truncation is indistinguishable from a quiet week. | **BUILT, but only as far as the anchor reaches** |
| Rewrite the whole chain with the key | Only the anchor catches this. Everything above verifies happily against a forged chain. 🔴 **Measured 2026-09-04: the anchor does not catch it either.** The anchor is signed with the same symmetric key, so the holder of that key rewrites the chain and signs a matching anchor. Until the signing key is separated, this row has no control behind it. | **NOT HELD** |
| Stop anchoring and hope nobody notices | Anchor liveness is a fact the compliance evaluator reads, and a stale witness on an advancing chain flips it false rather than being absent. There is also a metric for anchor age. | **BUILT** |

### Against the copy that leaves

The row that used to say "the destination is compromised, so both copies are the attacker's" is
answered above: that account is yours. What stays ours is everything up to the moment the copy lands,
plus noticing when it stops landing.

| Vector | Control | Status |
| --- | --- | --- |
| A destination stops accepting and nobody notices | Anchor liveness is a fact the compliance evaluator reads, and a stale witness on an advancing chain flips tamper protection false rather than going quiet. This is the control that makes a silently-dropping destination visible. | **BUILT** |
| History rewritten at the destination, for example a force push | Yours to prevent, and worth doing: protect the branch, or anchor to a locked object store instead. adamance records the head sequence it sent, so a destination missing entries it was given disagrees with what we hold. | **STATED** |
| Messages deleted or filtered at a mailbox | Same shape. A mailbox that silently drops looks like a quiet period from the outside, which is why liveness is checked from our side rather than inferred from theirs. | **STATED** |
| Anchors replayed or rolled back | ⚠️ Anchor sequences should be required to advance, and nothing enforces that yet. This one is ours, not yours, and it stays open. | **OPEN** |
| Audit contents leak to the destination | Yours. Entries carry principals, hostnames and actions, so pick a destination you would be comfortable holding that. The recommendation to start with git is about cost, not confidentiality. | **STATED** |
| Destination credentials stolen from the control plane | In the A4 case the attacker is already where those credentials live. Anchoring defends against a rewritten local chain, not against someone who owns the control plane and the destination at once. | **ACCEPTED** |
| Key rotation breaks chain continuity | The anchor records the producing key id, so a rotation is visible rather than a break. Continuity across a rotation is not otherwise designed. | **PARTIAL** |
| A forged anchor is accepted by a verifier | 🔴 **NOT HELD, measured 2026-09-04.** The anchor is signed with the audit chain's own symmetric key, so verifying an anchor and forging one are the same capability, and the row above this table that says only the anchor catches a full rewrite is therefore not true against anyone holding that key. Required: a named signing key that is not the HMAC chain key, an asymmetric signature so verifying does not confer forging, a distribution path for the public half that does not run through the box being audited, and a stated recovery if the private half is lost or copied. | **OPEN, and it is the one that decides the subsystem** |
| The local store is destroyed and the record cannot be reconstructed | ⭐ Added 2026-09-04. The anchor proves loss. It does not survive it. Required: a stated position on whether the event stream itself leaves the box, and to which of the four destinations, with the confidentiality consequence stated in the same breath because entries carry principals, hostnames and actions. It is the single largest design gap in this subsystem. | **NOT MODELLED** |
| A mutation succeeds and its entry never gets written | ⭐ Added 2026-09-04. This chain proves that what was written was not altered. Nothing here proves that everything was written, and an entry that was never appended is indistinguishable from an action that never happened. FreeIPA, Keycloak, Postgres and OPA cannot share a transaction with the audit append. Required: intent recorded before the mutation is attempted, outcome after, an explicit unconfirmed-mutation state when the outcome cannot be confirmed, reconciliation that resolves those states, and an append failure that fails the operation rather than being swallowed. | **NOT MODELLED** |
| The chain is complete and the clock under it is not | ⭐ Added 2026-09-04. Entry timestamps, anchor liveness and the staleness check that flips tamper protection false all trust a clock nobody authenticated. See TM-26 in the main threat model. | **NOT MODELLED** |

## What we do not defend against

- An attacker who holds the HMAC key and the anchor destination at the same time. There is no third
  copy, so there is nothing left to disagree with them. Anchoring to two destinations that do not
  share an account is the answer, and it is your call rather than ours.
- The security of the destination account. Stated above and repeated here because it is the single
  most important thing to understand about this subsystem.
- ⚠️ **Corrected 2026-09-04. This read: "Destruction of what is on the box. That is the premise, not
  a gap. The answer is that the copy already left." That answer is wrong in this document's own
  terms.** What leaves is the chain head, not the entries. So destruction of the local store is
  *detectable* and not *recoverable*: the anchor proves that a record existed and is gone, and cannot
  tell you what was in it. An anchor is a witness. It is not a copy of the record, and the sentence
  above quietly promised that it was. Preserving the events themselves off the box is a separate
  requirement, it is technically possible with the four destinations already designed, and it is now
  tracked as TMA2-06 rather than being answered by a sentence.
- Making the record complete *by choosing what to record*. The chain proves that what was written was
  not changed. It says nothing about what nobody thought to write. ⚠️ **Extended 2026-09-04: that is a
  statement about coverage and it was being read as covering atomicity too, which it does not.** An
  action nobody instrumented and an action that was instrumented, executed, and then failed to append
  look identical from here. The first is a scope decision. The second is a bug this document now
  requires a control for, above.

## Still open

| ID | Item | Why it is still open |
| --- | --- | --- |
| TMA2-01 | The four destinations are being built | Git, email, SSH or SCP and object storage are v1 scope. The tree has one sink today. |
| TMA2-02 | The setup prompt is being built | Install and first admin setup should recommend a destination without gating on it. |
| TMA2-03 | No rollback or replay protection on anchors | Nothing requires anchor sequences to advance, and unlike the destination rows this one is ours to fix. |
| TMA2-04 | A local read-only witness is unexplored | A USB device that adamance unlocks, writes and re-locks would give a default install a witness with no account and no network. Recorded as a question rather than a plan. |
| TMA2-06 | An anchor witnesses, it does not preserve — **and preservation is the answer, not a side note** | ⭐ 2026-09-04, ⚖️ **RULED and promoted to the primary control 2026-09-05.** Only the chain head leaves today, so destroying the local store lets you prove something is gone without saying what it was. ⇒ **Ship the events themselves, not just the head.** What has already left the machine is beyond an attacker who takes the machine afterwards — that is true by construction and it does not depend on the anchor's signature being unforgeable. Landed in a destination the control plane cannot rewrite (a git repository it cannot push to, write-once storage, a mailbox it does not hold), the full trail survives the compromise that the anchor alone can only testify about. ⚠️ **Corrected 2026-09-05, second pass. This row read "⚖️ RULED and promoted to the primary control" and "This dominates TMA2-07". The ranking was wrong and is withdrawn.** Preservation and provenance are not two controls to be ranked against each other. Under an asymmetric signer with a trust root outside this box, a preserved stream is evidence. Under the chain's own symmetric key it is bytes that agree with themselves, because verifying them needs the key and the key is on the machine the attacker took. Shipping the whole stream under that key does not answer TMA2-07, it enlarges it: the old failure was two disagreeing heads, and the new one is two complete histories that each verify, either of which can name an innocent person. That is fabricated evidence, and "a conflict is evidence" cannot tell it from the truth. Sharper still because of what this document recommends: git first, which exists to replicate and be searched, and write-once second, where a planted lie can never be corrected. ⇒ **Completeness, provenance and preservation are CONJUNCTIVE. None dominates.** What survives unchanged is the reason this row was written: a copy that already arrived cannot be un-sent, and against an append-only receiver the earlier history has a standing in time that a later forgery cannot manufacture. ⛔ Requires the destination to be genuinely append-only — a mailbox with a delete button is not one — and requires the verifier to read every anchor it holds rather than the newest. See TMA2-10 through TMA2-13, and TM-41 and TM-42, which are what this row cannot do alone. |
| TMA2-07 | The anchor signing key has no trust root | ⭐ 2026-09-04. Anchors are called signed throughout, and measurement says there is no anchor key: the record carries the chain's `key_id` and the off-box copy is a chain entry under the same HMAC key, so verification and forgery are one capability. |
| TMA2-08 | Audit completeness is not atomicity | ⭐ 2026-09-04. A cross-system mutation that lands while its audit append fails leaves a valid chain that is missing an event, and nothing reconciles that. |
| TMA2-09 | Anchor timestamps trust an unauthenticated clock | ⭐ 2026-09-04. Liveness and staleness are time-based and the time source is not a boundary anyone has described. See TM-26. |
| TMA2-10 | The window before an anchor fires, where nothing has to be rewritten | ⭐ 2026-09-05. Note the head the last anchor published; act; delete what you did and put the head back before the next tick. The next anchor extends the pruned chain and agrees with itself. No destination ever disagrees, nothing is forged, liveness stays green, and if the events ship on the same timer they never shipped either. 🔴 **Measured: `auditChainVerifyInterval = 5 * time.Minute` and the anchor publishes from that same tick, so the window is five minutes wide.** Every other row here argues about anchors that exist; this is how the damning ones never become anchors. Required: couple a mutation's success to a durable external acceptance, or state the maximum loss window out loud and shrink it. ⛔ A receipt read back on the control plane is not the control — the destination has to retain it and somebody off the box has to notice silence. |
| TMA2-11 | The only witness that exists today lives inside the boundary it is meant to witness | ⭐ 2026-09-05. The four destinations are v1 scope and unbuilt; `anchorSinkWazuh = "wazuh"` is the only sink in the tree, Wazuh ships as part of this same stack, and the gateway holds its indexer credentials. So today's witness is one the adversary in this document already owns. Until the four destinations land, everything above describes a shape rather than a defence. A witness must share no host, no administrative plane, no credential and no delete authority with the thing it witnesses; the writer gets append-only and somebody else holds retention. |
| TMA2-12 | One destination can show two histories, and a restore is indistinguishable from an attack | ⭐ 2026-09-05. Nothing gives a chain an identity, so a restore or a reimage produces a fork with the same signature as a rewrite — and once operators learn a conflict follows every restore, a conflict stops meaning anything. A single destination can also serve different histories to different readers. Required: an immutable stream identity per deployment and per restored incarnation, each new chain committing to its predecessor's last head, restores producing a signed and anchored transition record, and cross-published checkpoints or a witness quorum so one destination cannot split the view. |
| TMA2-13 | Nothing says what happens when the witness is unreachable | ⭐ 2026-09-05. If governed mutations carry on while no witness is accepting, that is a deliberate audit-loss mode and it should be written down as one. If they stop, the witness is now an availability dependency and a denial-of-service target. Both are defensible; neither is stated. Also unstated: how a write-once destination is ever corrected, since an immutable false accusation cannot be quietly overwritten and needs an append-only revocation instead. |
| TMA2-05 | WORM verification is unspecified | Object locking is the strongest destination on offer and nothing states how we confirm it is actually on. |

## Where this came from

The code named above: `src/api-gateway/internal/storage/auditchain/store.go`,
`src/common/audit/chain.go`,
`src/api-gateway/internal/handlers/compliance/auditstate.go`.
