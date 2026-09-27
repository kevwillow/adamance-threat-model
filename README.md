# adamance threat models

The security contract adamance is built to meet, published before the code that has to meet it.

**adamance** is self-hosted identity, access and audit for Linux. One console for logins, for what
each person may touch, and for a record of what they did, from a single machine to a fleet. Built on
FreeIPA, Keycloak, OPA, step-ca, Wazuh and OpenBao. AGPL-3.0. [adamance.dev](https://adamance.dev)

## What these documents are

A threat model is where you write down how a thing fails before you decide how it works: who would
abuse it, what they would get, and what stops them. That document exists before the code does, and
the model writing the code gets handed it along with the spec.

These started as the contract. They are now also the record of checking the code against it. Rows
carry the date they were last verified, and where someone went and looked, the file and the line they
looked at. A row saying a control is confirmed is a claim about specific source on a specific date,
so you can see exactly what it rests on.

Where the code does not meet a line in here, the line is the requirement and the code is the work.

The source is not public yet, so the file references point somewhere you cannot follow today. They
are published anyway. When the source opens, every one of them can be checked.

| Document | Edited | Covers |
| --- | --- | --- |
| [THREAT_MODEL.md](THREAT_MODEL.md) | 2026-05-24 to 2026-09-26 | The control plane. Identity, enrollment, policy distribution, lateral movement, and the operators themselves. |
| [THREAT_MODEL_agent_accounts.md](THREAT_MODEL_agent_accounts.md) | 2026-09-01 to 2026-09-26 | Accounts held by AI agents. Written assuming the agent can be talked into anything. |
| [THREAT_MODEL_installer.md](THREAT_MODEL_installer.md) | 2026-09-01 to 2026-09-26 | The installer and the supply chain behind it, including the part nobody can engineer away. |
| [THREAT_MODEL_audit_anchoring.md](THREAT_MODEL_audit_anchoring.md) | 2026-09-01 to 2026-09-26 | The audit chain and the copy that leaves the box. |
| [THREAT_MODEL_session_recording.md](THREAT_MODEL_session_recording.md) | 2026-09-01 to 2026-09-26 | Recording privileged sessions, and the one deliberate exception. |
| [THREAT_MODEL_samba_ad_dc.md](THREAT_MODEL_samba_ad_dc.md) | 2026-09-01 to 2026-09-26 | The optional module that makes adamance the domain itself. |
| [THREAT_MODEL_network_modules.md](THREAT_MODEL_network_modules.md) | 2026-09-01 to 2026-09-26 | VPN, RADIUS and DNS. The modules that authenticate things adamance does not manage. |
| [THREAT_MODEL_ad_integration.md](THREAT_MODEL_ad_integration.md) | 2026-09-01 to 2026-09-26 | Keeping the Active Directory you already run. |

The control plane model has been in revision since May 2026 and its header lists every review date.
The seven subsystem models were added on 2026-09-01. Four of them, and the control plane model, were
corrected and extended on 2026-09-04, and five were corrected again on 2026-09-05. Each file repeats
its own dates in its header.

On 2026-09-26 all eight were brought level with the copies kept beside the source, which went on
being re-measured against the code through 2026-09-24. The rows this repository corrected on its own on
2026-09-05 were kept.
Later the same day an outside review of all eight added seventeen rows and corrected, in place, every
contradiction it found that survived checking. What it found, and what was refused, is under
[What is not claimed](#what-is-not-claimed).

## Read the corrections first

⭐ The most useful sections in here are the ones headed **Corrections**. A threat model that only ever
gained rows would tell you nothing about whether anyone was checking it.

Those sections record cases where a previous version of a document was wrong, with the false text
quoted next to what replaced it. One row claimed a control was verified when nothing implemented it,
and several review passes read that row and looked elsewhere. Another recorded a refusal that turned
out to be an absence which happened to produce the same answer.

A gap nobody has examined is ordinary. A gap with a tick beside it is worse.

### Who caught what

⚖️ These threat models were researched and drafted with a rig of AI models. The maintainer designed
that rig and directed it, and he read all of it, end to end, while the work was being planned. Where
a model was wrong he overruled it. Where a model was right, including when it overturned something
he had written, he accepted it and let it land.

That is the part the models cannot supply. They are fast, they are often right, and several of them
agreeing is not evidence that they are. What separates vibe-coded output from work you can rely on is
not which model wrote the first draft. It is a person in the middle who understands the system, checks
every conclusion, and knows when a model is wrong and why.

The corrections record that judgement instead of hiding it. Some carry **OPERATOR REFUTED** or
**OPERATOR ACCEPTED**, which say which reversals came from the maintainer and which came from the
models or an outside reviewer. A document that absorbs every correction into one anonymous voice
tells you nothing about where its judgement comes from.

- **OPERATOR REFUTED** — the models had converged on something and the maintainer overturned it.
- **OPERATOR ACCEPTED** — a model or a reviewer overturned something, including a conclusion written
  in the maintainer's favour, and he ruled it correct and let it land.

The clearest example is in [the anchoring model](THREAT_MODEL_audit_anchoring.md), and it is there
because it reverses twice in two days in opposite directions. Two models concluded the whole subsystem
was worth nothing against a control-plane insider, on the reasoning that the anchor is signed with the
audit chain's own symmetric key, so verifying an anchor and forging one are the same capability. That
is true and it is not the whole picture. The maintainer overturned it the same day: the models had
overlooked off-box anchoring. What has already been shipped off the box is out of reach by design,
and an attacker who takes the control plane afterwards cannot erase it.

The models had treated the anchor as a purely cryptographic object. A destination is also a witness in
time: it orders and timestamps what arrives, and that ordering is not a property of the payload or of
the key that signed it. Somebody who takes the key afterwards gets a *conflicting* history, not the
erasure of the one already sent.

Then the correction was over-applied — preservation got promoted to the primary control — and two
later reviewers overturned *that*, because a preserved stream under the same symmetric key is bytes
that agree with themselves. The maintainer ratified the withdrawal rather than defending the row
written in his favour. That one is marked ACCEPTED.

Both wordings are still on the row, the withdrawn text quoted.

The commit history here runs from the first draft in May 2026 and has not been squashed. If you want
to know when a claim appeared, when it was contradicted, and what it said before it was corrected,
`git log -p` on any of these files will tell you. Contributor email addresses were collapsed onto one
address before publication. Author names are untouched, so a change still names whoever drafted it.
Nothing else in the history was edited, apart from one commit subject reworded on 2026-09-26, the day
it was pushed; no file changed in that commit.

## How the contract gets checked

A **proof harness** ships with the code and runs against a live deployment. A proof is not a test: a
test asserts that a function returns an error, while a proof breaks a real dependency on a running
system, watches whether the operation that should now be refused is refused, then restores it and
confirms recovery.

It reports four verdicts, and two of them exist so that "I could not tell" can never be dressed up as
a pass:

- **Proven.** The same probe succeeded before the fault was injected, the fault was independently
  confirmed live, the probe was refused, and the service recovered after restore. Anything less is
  not a pass.
- **Failed.** The fault was live and the operation went through anyway.
- **Not proven.** The check could not run.
- **Inconclusive.** It ran and the evidence does not support a verdict.

A check never reports its own verdict. It supplies mechanism only, and the runner does the
comparison, because a check that reports its own outcome can report a confident pass having done
nothing at all.

## What is not claimed

Nobody outside the project has audited this. No external reviewer has been through the code and come
back with a verdict. That review happens before the first release, and when it does, what they found
and what changed will be recorded here.

⭐ **2026-09-04.** The documents were read end to end by someone outside the project, against the
published commit, and that read found six rows that had gone stale and one that named an enforcement
mechanism which does not exist in the tree. It also found real gaps: an anchor witnesses a record
rather than preserving it, a certificate with a hostname in it is not bound to that machine, an
approval that counts approvers does not bind to what was approved, and a chain that proves nothing was
altered proves nothing about what was never written. All six corrections are in place and quote what
they replaced, and the gaps are carried as requirements with an honest status. This was a read of the
documents, not an audit of the code, and it does not change the paragraph above.

⭐ **2026-09-05.** The same outside reader went through the corpus again, and four more models were
put on it independently — three of them from families that had no hand in writing any of it. The
finding they agreed on was not a missing threat. It was **synchronization**: the corpus contained the
new correct conclusion and several active summaries of the superseded one at the same time, because
corrections were being filed on the row that was wrong and not propagated to every other row that
repeated it. Fourteen of those are now corrected in place, each quoting what it replaced.

Two of the reviewers' findings could not be settled by reading the documents, so they were measured
against the source, and both were worse than reported. The control that claimed to make a
silently-dropping destination visible reads a *local* record and cannot see the destination at all,
and it was carried as **BUILT**. And the store that records anchors discards a conflicting one
silently, which is the exact evidence a restore-versus-attack check needs. That one has since been fixed:
since 2026-09-23 a conflicting anchor is refused and recorded.

The reviewers also disagreed with the outside read in one place and were right to: a row stating a
requirement was read as a claim that the requirement was met. That row now says so, because
mistaking this document's contract rows for status rows is the most likely way to get it wrong.

⭐ **2026-09-26.** Three more reviewers read all eight models end to end, each given a different job:
Perplexity read them as a design-assurance artefact, OpenAI's gpt-6-astra was asked for threats no row
covers, and Anthropic's Fable 5.1 was asked whether the eight hold together as one contract. Between
them they added seventeen rows (first-install authority, which tokens each service may accept, host
authentication for SSH, secrets leaking into logs, and more) and found rows that contradicted each other
or the documents' own reading rule. Every status change they proposed was measured against the source
before it landed. One finding did not survive that: a reviewer concluded that an AI agent would clear
every step-up check once an operator switched off the MFA requirement, and the policy refuses a subject
that is not a human user before that switch is ever read. Some things the reviewers read as gaps were
already built, in whole or in part, and those rows now say so with the file and line.

Several recommendations were refused on principle: narrowing the MFA, non-repudiation, agent-account,
Samba, DNS and ARM64 claims until the code catches up. These documents are the contract, so a claim that
can be built stays. One requirement was changed because it could never be met: a server cannot see
whether a TLS client checked its certificate, so the row that asked the gateway to refuse an unverified
bootstrap now asks for the achievable, stronger thing. The corrections quote what they replaced, and the
new rows are marked NOT MEASURED until someone measures them.

⛔ **What this still is not.** Nobody has audited the code. Five models reading nine markdown files
is not an audit, no matter how many of them agree, and where a finding rests on source that only the
maintainer can see, the row says so rather than borrowing their confidence.

## Contributing

Found something wrong, thin, or too confident? Open an issue. A threat model gets better by being
argued with, and a finding against a document is cheaper than a finding against a deployment.

## Licence

AGPL-3.0, the same as adamance.
