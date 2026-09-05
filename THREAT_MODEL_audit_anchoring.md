# Threat Model: the audit chain and its off-box copy

> Status: **DRAFT, written 2026-09-01** against `b276339c`, corrected and extended 2026-09-04,
> and twice on 2026-09-05. Owner: project maintainer.
>
> ⚖️ **This subsystem has now reversed itself twice, and the two reversals were caught by different
> people. That is the most useful thing on the page, so it is stated at the top rather than buried.**
> The first: two models concluded the subsystem was worth nothing against A4 because the anchor is
> signed with the chain's own key, and **the maintainer overturned it** — an anchor that already
> reached a destination the control plane cannot rewrite is beyond somebody who takes the key
> afterwards. The second: that correction was then over-applied into a ranking, preservation was
> promoted to the primary control, and **two later reviewers overturned that** — completeness,
> provenance and preservation are conjunctive and none of them dominates. The maintainer ratified
> the withdrawal rather than defending the row written in his favour. Both wordings are on the
> TMA2-06 row with the withdrawn text quoted, and the rows carry ⚖️ **OPERATOR REFUTED** or
> ⚖️ **OPERATOR ACCEPTED** so you can tell which reversals were his and which were not.
>
> ⭐ **A third pass on 2026-09-05 found the ruling still one conjunct short.** Truthful attribution
> (TM-42) survives all three of the named properties holding, so there are four, not three — and
> "none dominates" answers only *which single control suffices*, never *what to build first*. The
> row now states precedence separately from sufficiency. Rows TMA2-10 to TMA2-15 were added across
> the two 09-05 passes, and the reason they are worth reading is that each describes a way the
> subsystem fails while every check it currently performs still passes.
>
> Companion to [`THREAT_MODEL.md`](THREAT_MODEL.md), which covers who may do what. This one
> covers whether you can still prove it afterwards.

---

## What this is for

The audit chain is the thing that survives the attack. Every other control here is about stopping
something. This one is about the morning after, when the question is what happened and whether the
record of it can be trusted.

Two properties, and they are not the same:

**Tamper-evident.** You can prove entries were altered, inserted, deleted or reordered. Built. ⚠️ **Qualified
2026-09-05: "Built" on its own overstates this, and the rest of the document says so.** It holds against
somebody without the chain key. Against somebody holding it, a full rewrite re-chains and verifies
(TMA2-07); a deletion inside the five-minute window before an anchor fires leaves nothing to disagree
with (TMA2-10); and a truncation with no anchor behind it is indistinguishable from a quiet week. Read
it as *tamper-evident against an adversary without the key, and only as far back as the last anchor
that actually left*.

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
demonstrating it.

⚠️ **Corrected 2026-09-05, second pass. This paragraph used to end "and it is the part of this
subsystem I am most confident in." That sentence has not survived its own document.** What the three
inputs demonstrate is narrower than the control's name: the key is configured, the chain agrees with
itself, and a *local* anchor row is fresh. The same document now measures that the anchor key is the
chain key (TMA2-07), that the only live witness sits inside the boundary it is meant to witness
(TMA2-11), that a five-minute window leaves liveness green while the damning entries are removed
(TMA2-10), and that the liveness input does not depend on the off-box copy landing at all (the
destination row below). Against a patient key-holder this control demonstrates very little. It is
still worth having against a clumsy one, and that is the honest size of the claim.

## Where the copy goes, and whose problem it is

Four destinations, all in v1. A signed copy of the chain head leaves the box on a timer to any of
them:

**A git repository.** The anchor chain becomes a commit history, which is content-addressed and
cheap to hold somewhere else. Recommended first because it costs nothing.

**An email account.** A mailbox is timestamped by somebody else, which is the property worth having. ⚠️ **Corrected 2026-09-05, second pass. This read "A mailbox is an append-only log that somebody else timestamps for you."** It is not an append-only log — TMA2-06 says so in this same document: a mailbox with a delete button is not one. What it gives you is an external receipt trail and an arrival ordering the control plane does not author. What it does not give you is retention you can rely on.

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
| 1= | The anchor signing key | ⭐ Added 2026-09-04. Anchors are described throughout this document as signed and this key was in no asset list. Forge an anchor and the one witness that catches a rewritten chain agrees with the rewrite, which collapses row 1 and this row into a single compromise. 🔴 **Measured 2026-09-04: it is the HMAC chain key, so anyone who can verify an anchor can forge one.** ⚖️ **OPERATOR REFUTED, 2026-09-04. That sentence used to continue "and the subsystem is worth nothing against A4". Two models had converged on it and the maintainer overturned it the same day, before any reviewer found it:** *"I think everyone is overlooking the fact of off box anchoring... WHAT GETS SHIPPED OUTSIDE OF ADAMANCE IS SAFE, by design! the head hash or tail or whatever the fuck gpt said is irrelevant. an attacker cant erase whats already shipped out."* The reasoning error the models made is worth naming, because it is not obvious: they treated the anchor as a purely cryptographic object, so a symmetric key made verification and forgery one capability and the whole thing looked worthless. That collapses *unforgeable* into *evidentiary*. A destination is also a **temporal witness** — it independently orders and timestamps arrival, and that ordering is not a property of the payload or of the key that signed it. An anchor that has ALREADY REACHED a destination the control plane cannot rewrite is beyond the reach of somebody who takes the key afterwards. Holding the key buys a *conflicting* history, not the erasure of the one already sent — and a conflict is itself evidence, provided the verifier reads every anchor it has rather than only the newest, and the destination genuinely cannot be rewritten. What the symmetric key actually costs is narrower and still serious: verification cannot be handed to anyone without handing them forgery along with it, and a private half that lives on the control plane does not escape A4 whatever algorithm signs with it. ⚠️ **Corrected 2026-09-05, second pass. This row read "⇒ The dominant control here is the DESTINATION, not the key. See TMA2-06, which is the answer this row was reaching for." That ranking was withdrawn by TMA2-06's own correction later the same day, and this sentence outlived the ruling it pointed at.** The destination is not dominant either. Under the chain's own symmetric key a preserved stream is bytes that agree with themselves, so a destination the control plane genuinely cannot rewrite still holds a history the key-holder may have fabricated before it was sent. ⇒ **Completeness, provenance and preservation are CONJUNCTIVE. None dominates.** See TMA2-06. There is no separate anchor signing key. `WriteAnchor` (`src/api-gateway/internal/storage/auditchain/store.go:512`) stores the chain's own `key_id`, and the off-box copy is `emitAuditChainAnchor`'s `iam.audit.chain_anchor` event (`src/api-gateway/cmd/server/main.go:7253`) routed back through the same `ChainEmitter`. See TMA2-07. |
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
your mailbox. ⚠️ **Two corrections here, 2026-09-05.** First, "an honest record of what was sent" is
more than this system can owe against its own adversary: TM-42 establishes that a compromised producer
signs whatever it likes, so what adamance can actually owe is *what the producer asserted it sent* and
*what a destination confirms it received* — two claims, not one. Second, the boundary and TMA2-12 are
in tension: that row requires cross-published checkpoints or a witness quorum precisely so one
destination cannot serve different histories to different readers, which is a control aimed at A10's
behaviour, inside a boundary this paragraph puts outside the model. Either the boundary moves to cover
destination equivocation, or that requirement becomes advice about choosing destinations. It is
currently written as ours and disclaimed as yours.

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
| A destination stops accepting and nobody notices | ⚠️ **Corrected 2026-09-05, second pass. This row read "Anchor liveness is a fact the compliance evaluator reads, and a stale witness on an advancing chain flips tamper protection false rather than going quiet. This is the control that makes a silently-dropping destination visible." It is not that control and it never was.** 🔴 **Measured 2026-09-05:** the liveness signal is refreshed from the LOCAL anchor write, before the off-box publish is attempted. `WriteAnchor` records the local row (`src/api-gateway/cmd/server/main.go:7234`), the anchor-age gauge is reset to zero on the next line (`:7238`), and only then is the off-box copy attempted (`:7243`) — where a failure is logged and the function returns. The compliance evaluator reads that local freshness (`src/api-gateway/internal/handlers/compliance/auditstate.go:67-72`) and folds it into `audit_tamper_protection_enabled` and `logs_immutable`. So a destination that has never accepted anything still reports `audit_offbox_anchoring_live: true`. The code is more honest than this document was: the comment at the emit call already says the local row alone is not an independent witness. ⇒ The control this row claimed requires the destination's own retention to be read back from off the box, by something the control plane cannot answer for. Nothing does that today. | 🔴 **NOT HELD** |
| History rewritten at the destination, for example a force push | Yours to prevent, and worth doing: protect the branch, or anchor to a locked object store instead. adamance records the head sequence it sent, so a destination missing entries it was given disagrees with what we hold. ⚠️ **Narrowed 2026-09-05: under A4 "what we hold" is the attacker's too.** The local record of what was sent lives on the box being audited, so a rewrite rewrites it as well and the disagreement this row offers never appears. The check works against a destination-side fault or a third party, which is worth having; it does not work against the adversary this document is written for. What would work is a receipt the *destination* retains and somebody off the box reads back. | **STATED** |
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
  share an account helps, and it is your call rather than ours. ⚠️ **Narrowed 2026-09-05: this said
  two destinations were "the answer", and they are an answer to one attacker only.** They defeat
  deletion and equivocation by somebody who holds the key and *one* destination, and only where
  honest earlier checkpoints already landed somewhere they cannot reach. They do nothing against a
  key-holder who publishes the same fabricated history to both, because both copies then agree and
  agreement is not truth. The advice stands; the word "answer" did not.
- The security of the destination account. Stated above and repeated here because it is the single
  most important thing to understand about this subsystem. ⚠️ **Disambiguated 2026-09-05: three of
  four reviewers read this as the withdrawn "the destination is the dominant control" ranking in
  reader-facing dress.** It is not that claim and is not meant as one. It is a statement about where
  *your* work is: this is the part of the subsystem adamance cannot do for you. On the evidentiary
  question, preservation does not outrank completeness, provenance or attribution — see TMA2-06.
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
| TMA2-05 | WORM verification is unspecified | Object locking is the strongest destination on offer and nothing states how we confirm it is actually on. ⚠️ **Reordered 2026-09-05: this row printed after TMA2-13 and has been moved back into sequence.** |
| TMA2-06 | An anchor witnesses, it does not preserve — ⚠️ **title corrected 2026-09-05: this read "and preservation is the answer, not a side note", which is the ranking the row itself withdraws below** | ⭐ 2026-09-04, ⚖️ **RULED and promoted to the primary control 2026-09-05.** Only the chain head leaves today, so destroying the local store lets you prove something is gone without saying what it was. ⇒ **Ship the events themselves, not just the head.** What has already left the machine is beyond an attacker who takes the machine afterwards — that is true by construction and it does not depend on the anchor's signature being unforgeable. Landed in a destination the control plane cannot rewrite (a git repository it cannot push to, write-once storage, a mailbox it does not hold), the full trail survives the compromise that the anchor alone can only testify about. ⚠️ **Corrected 2026-09-05, second pass. This row read "⚖️ RULED and promoted to the primary control" and "This dominates TMA2-07". The ranking was wrong and is withdrawn.** Preservation and provenance are not two controls to be ranked against each other. Under an asymmetric signer with a trust root outside this box, a preserved stream is evidence. Under the chain's own symmetric key it is bytes that agree with themselves, because verifying them needs the key and the key is on the machine the attacker took. Shipping the whole stream under that key does not answer TMA2-07, it enlarges it: the old failure was two disagreeing heads, and the new one is two complete histories that each verify, either of which can name an innocent person. That is fabricated evidence, and "a conflict is evidence" cannot tell it from the truth. Sharper still because of what this document recommends: git first, which exists to replicate and be searched, and write-once second, where a planted lie can never be corrected. ⇒ **Completeness, provenance and preservation are CONJUNCTIVE. None dominates.** ⚖️ **OPERATOR ACCEPTED, 2026-09-04.** This second reversal was not the maintainer's catch and is not claimed as one: a third reviewer and a fourth found that the promotion over-applied his point into a ranking, and he ratified the withdrawal rather than defending the row written in his favour — *"yes if we've come to a consensus then update the docs... make sure to keep the full threat model history."* What survives unchanged is the reason this row was written: a copy that already arrived cannot be un-sent, and against an append-only receiver the earlier history has a standing in time that a later forgery cannot manufacture. ⭐ **Extended 2026-09-05, third pass, and this is the part the ruling above still gets wrong.** The row names three conjuncts and this document already contains four. TM-42 establishes that **truthful attribution** survives all three of these holding: a record can have perfect provenance — a real key, a trust root off the box — and still name the wrong person, because the `actor` field is one the producer fills in. Attribution is not a sub-case of provenance and must be counted separately. ⛔ **And "none dominates" answers only one question.** It answers *"which single control is sufficient?"* — none of them. It is read as *"no priorities exist"*, which this document does not believe: TM-41 is labelled "the first thing to fix" and TM-31 was labelled "highest priority" a day earlier, in the same table, unreconciled. The two questions must stop being answered with one sentence. **Precedence, stated separately from sufficiency:** completeness is *prior*, not a peer — a record that was never written cannot be preserved, signed or attributed, which is TM-41's own argument. Then preservation, because temporal standing cannot be created retroactively and every day without a destination is evidence that can never be recovered. Then provenance, which is the most expensive and buys nothing on its own while the chain can be bypassed. Then attribution, which needs cryptography at the client and is the hardest. Necessity has no order; construction does. ⛔ Requires the destination to be genuinely append-only — a mailbox with a delete button is not one — and requires the verifier to read every anchor it holds rather than the newest. See TMA2-10 through TMA2-15, and TM-41 and TM-42, which are what this row cannot do alone. |
| TMA2-07 | The anchor signing key has no trust root | ⭐ 2026-09-04. Anchors are called signed throughout, and measurement says there is no anchor key: the record carries the chain's `key_id` and the off-box copy is a chain entry under the same HMAC key, so verification and forgery are one capability. |
| TMA2-08 | Audit completeness is not atomicity | ⭐ 2026-09-04. A cross-system mutation that lands while its audit append fails leaves a valid chain that is missing an event, and nothing reconciles that. |
| TMA2-09 | Anchor timestamps trust an unauthenticated clock | ⭐ 2026-09-04. Liveness and staleness are time-based and the time source is not a boundary anyone has described. See TM-26. |
| TMA2-10 | The window before an anchor fires, where nothing has to be rewritten | ⭐ 2026-09-05. Note the head the last anchor published; act; delete what you did and put the head back before the next tick. The next anchor extends the pruned chain and agrees with itself. No destination ever disagrees, nothing is forged, liveness stays green, and if the events ship on the same timer they never shipped either. 🔴 **Measured: `auditChainVerifyInterval = 5 * time.Minute` and the anchor publishes from that same tick, so the window is five minutes wide.** Every other row here argues about anchors that exist; this is how the damning ones never become anchors. Required: couple a mutation's success to a durable external acceptance, or state the maximum loss window out loud and shrink it. ⛔ A receipt read back on the control plane is not the control — the destination has to retain it and somebody off the box has to notice silence. |
| TMA2-11 | The only witness that exists today lives inside the boundary it is meant to witness | ⭐ 2026-09-05. The four destinations are v1 scope and unbuilt; `anchorSinkWazuh = "wazuh"` is the only sink in the tree, Wazuh ships as part of this same stack, and the gateway holds its indexer credentials. So today's witness is one the adversary in this document already owns. Until the four destinations land, everything above describes a shape rather than a defence. A witness must share no host, no administrative plane, no credential and no delete authority with the thing it witnesses; the writer gets append-only and somebody else holds retention. |
| TMA2-12 | One destination can show two histories, and a restore is indistinguishable from an attack | ⭐ 2026-09-05. Nothing gives a chain an identity, so a restore or a reimage produces a fork with the same signature as a rewrite — and once operators learn a conflict follows every restore, a conflict stops meaning anything. A single destination can also serve different histories to different readers. Required: an immutable stream identity per deployment and per restored incarnation, each new chain committing to its predecessor's last head, restores producing a signed and anchored transition record, and cross-published checkpoints or a witness quorum so one destination cannot split the view. ⭐ **Extended 2026-09-05: this row said "a signed and anchored transition record" and never said WHO signs it, which leaves the requirement circular.** If the compromised control plane signs the new incarnation, an attacker manufactures a restore that looks authorised. The transition needs an authority the compromised signer does not hold: the expected predecessor head fetched from the *witness* rather than the local store, a new immutable incarnation identifier, authorisation by an offline recovery key or an external quorum or the destination itself, a reason and snapshot identifier, and cross-publication before the new stream becomes authoritative. An unlinked incarnation is a fork, not a valid reset. ⛔ One exception, or catastrophic recovery becomes impossible: where the predecessor genuinely cannot be recovered, an unlinked incarnation may start **quarantined** and non-authoritative pending external approval, and must be labelled as such rather than silently adopted. |
| TMA2-13 | Nothing says what happens when the witness is unreachable | ⭐ 2026-09-05. If governed mutations carry on while no witness is accepting, that is a deliberate audit-loss mode and it should be written down as one. If they stop, the witness is now an availability dependency and a denial-of-service target. Both are defensible; neither is stated. Also unstated: how a write-once destination is ever corrected, since an immutable false accusation cannot be quietly overwritten and needs an append-only revocation instead. |
| TMA2-14 | Concurrent append, retry and failover are not modelled anywhere | ⭐ **2026-09-05.** The whole published corpus is silent on what happens with more than one emitter or more than one attempt. Two emitters racing from the same previous head; a timed-out append that may or may not have committed, retried, producing a duplicate; a sequence allocated while the event fails to persist; a mutation that succeeds once and is executed twice by reconciliation; two different events reusing one idempotency key; a failover gateway starting from stale chain state. HA is itself an open decision (TM-01), which is why this was never reached. Required as **observable behaviour**, not as one database design: head and sequence allocation that is linearizable, append and head advancement that commit together, a stable operation identifier fixed before the mutation, a retry that returns the original outcome instead of acting again, and a conflicting reuse that is an error and never "idempotent". 🔴 **Measured 2026-09-05, and in one place it is worse than an omission:** `WriteAnchor` (`src/api-gateway/internal/storage/auditchain/store.go:513-520`) swallows the unique violation keyed on `anchor_seq` alone, so a *different* head hash at an already-anchored sequence is discarded and returns success. That is exactly the fork and equivocation evidence TMA2-12 requires, and the store is structurally unable to record it. The swallow is deliberate and documented as idempotent restart handling; it is only idempotent if the colliding row is identical, and nothing checks that. |
| TMA2-15 | The anchor signer has no hardware option on the table | ⭐ **2026-09-05. Raised by the maintainer, 2026-09-04, and not in this document until now:** *"we also need to add hardware key support to this too if its doesn't support it already."* Every proposed fix for TMA2-07 so far has been an asymmetric key in software, and this document's own correction says a private half living on the control plane does not escape A4 whatever algorithm signs with it. A key in hardware that the control plane can use but not extract is the difference between those two sentences. Required: a stated position on TPM or HSM or a smartcard for the anchor signer, the behaviour when the device is absent, and how the public half is distributed. |

## Where this came from

The code named above: `src/api-gateway/internal/storage/auditchain/store.go`,
`src/common/audit/chain.go`,
`src/api-gateway/internal/handlers/compliance/auditstate.go`.
