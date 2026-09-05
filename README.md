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
| [THREAT_MODEL.md](THREAT_MODEL.md) | 2026-05-24 to 2026-09-04 | The control plane. Identity, enrollment, policy distribution, lateral movement, and the operators themselves. |
| [THREAT_MODEL_agent_accounts.md](THREAT_MODEL_agent_accounts.md) | 2026-09-01 to 2026-09-04 | Accounts held by AI agents. Written assuming the agent can be talked into anything. |
| [THREAT_MODEL_installer.md](THREAT_MODEL_installer.md) | 2026-09-01 | The installer and the supply chain behind it, including the part nobody can engineer away. |
| [THREAT_MODEL_audit_anchoring.md](THREAT_MODEL_audit_anchoring.md) | 2026-09-01 to 2026-09-05 | The audit chain and the copy that leaves the box. |
| [THREAT_MODEL_session_recording.md](THREAT_MODEL_session_recording.md) | 2026-09-01 to 2026-09-04 | Recording privileged sessions, and the one deliberate exception. |
| [THREAT_MODEL_samba_ad_dc.md](THREAT_MODEL_samba_ad_dc.md) | 2026-09-01 | The optional module that makes adamance the domain itself. |
| [THREAT_MODEL_network_modules.md](THREAT_MODEL_network_modules.md) | 2026-09-01 to 2026-09-04 | VPN, RADIUS and DNS. The modules that authenticate things adamance does not manage. |
| [THREAT_MODEL_ad_integration.md](THREAT_MODEL_ad_integration.md) | 2026-09-01 | Keeping the Active Directory you already run. |

The control plane model has been in revision since May 2026 and its header lists every review date.
The seven subsystem models were added on 2026-09-01. Four of them, and the control plane model, were
corrected and extended on 2026-09-04. Each file repeats its own dates in its header.

## Read the corrections first

⭐ The most useful sections in here are the ones headed **Corrections**. A threat model that only ever
gained rows would tell you nothing about whether anyone was checking it.

Those sections record cases where a previous version of a document was wrong, with the false text
quoted next to what replaced it. One row claimed a control was verified when nothing implemented it,
and several review passes read that row and looked elsewhere. Another recorded a refusal that turned
out to be an absence which happened to produce the same answer.

A gap nobody has examined is ordinary. A gap with a tick beside it is worse.

The commit history here runs from the first draft in May 2026 and has not been squashed. If you want
to know when a claim appeared, when it was contradicted, and what it said before it was corrected,
`git log -p` on any of these files will tell you. Contributor email addresses were collapsed onto one
domain before publication. Nothing else in the history was edited.

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

## Contributing

Found something wrong, thin, or too confident? Open an issue. A threat model gets better by being
argued with, and a finding against a document is cheaper than a finding against a deployment.

## Licence

AGPL-3.0, the same as adamance.
