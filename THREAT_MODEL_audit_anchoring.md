# Threat Model: the audit chain and its off-box copy

> Status: **DRAFT, first pass, written 2026-09-01** against `b276339c`. Owner: project maintainer.
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
| Rewrite the whole chain with the key | Only the anchor catches this. Everything above verifies happily against a forged chain. | **PARTIAL** |
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

## What we do not defend against

- An attacker who holds the HMAC key and the anchor destination at the same time. There is no third
  copy, so there is nothing left to disagree with them. Anchoring to two destinations that do not
  share an account is the answer, and it is your call rather than ours.
- The security of the destination account. Stated above and repeated here because it is the single
  most important thing to understand about this subsystem.
- Destruction of what is on the box. That is the premise, not a gap. The answer is that the copy
  already left.
- Making the record complete. The chain proves that what was written was not changed. It says nothing
  about what nobody thought to write.

## Still open

| ID | Item | Why it is still open |
| --- | --- | --- |
| TMA2-01 | The four destinations are being built | Git, email, SSH or SCP and object storage are v1 scope. The tree has one sink today. |
| TMA2-02 | The setup prompt is being built | Install and first admin setup should recommend a destination without gating on it. |
| TMA2-03 | No rollback or replay protection on anchors | Nothing requires anchor sequences to advance, and unlike the destination rows this one is ours to fix. |
| TMA2-04 | A local read-only witness is unexplored | A USB device that adamance unlocks, writes and re-locks would give a default install a witness with no account and no network. Recorded as a question rather than a plan. |
| TMA2-05 | WORM verification is unspecified | Object locking is the strongest destination on offer and nothing states how we confirm it is actually on. |

## Where this came from

The code named above: `src/api-gateway/internal/storage/auditchain/store.go`,
`src/common/audit/chain.go`,
`src/api-gateway/internal/handlers/compliance/auditstate.go`.
