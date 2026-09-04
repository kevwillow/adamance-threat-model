# Threat Model: session recording

> Status: **DRAFT, written 2026-09-01** against `b276339c`, corrected and extended 2026-09-04. Owner: project maintainer.
> Companion to [`THREAT_MODEL.md`](THREAT_MODEL.md) and
> [`THREAT_MODEL_audit_anchoring.md`](THREAT_MODEL_audit_anchoring.md). The audit chain records
> that something was allowed. Recording is what shows you what was then done with it.

---

## What this is for

On the host groups where you turn it on, a privileged session is captured, signed and replayable. ⚠️ **Build status, 2026-09-04: capture and signing are built, playback is not.** The player component is placed on the console page and never loaded, so a recorded session cannot currently be watched. That makes every row in this document about *reading* a recording a statement about the authorization path rather than about a working viewer, and it is why TMSR-05 is written as a requirement. The
strong version of the claim is that if it is not recording, it is not happening: the session is
refused rather than allowed to run uncaptured.

That claim is real and it is enforced at connect time. It also has one deliberate exception, and this
document exists mostly to describe that exception properly, because a control with an undocumented
escape hatch is worse than one without.

## The two design decisions that shape everything else

**The recorder holds no signing key, on purpose.** It runs as the logged-in operator. Give it a key
and you have given the operator a key to forge their own transcript with. So the recorder produces
bytes and the **gateway** signs them (`src/client-agent/internal/recorder/ingest_doc.go:10`). The
consequence is honest and stated in the code: between the recorder and the collector the *sender* is
authenticated by `SO_PEERCRED`, which cannot be spoofed, and the *content* is not authenticated at
all, because there is nothing on that side that could authenticate it.

**A session that cannot be durably captured is refused.** `decideSSHSessionGate`
(`src/client-agent/internal/recorder/ssh_command_audit.go:155`) is the connect-time gate. Unwritable
spool and no break-glass means the session does not start.

## Break-glass, which is the exception you need to know about

There is a root-owned sentinel file. If it is present, sessions proceed even when they cannot be
recorded (`src/client-agent/internal/recorder/ssh_recorder.go:318`). Under break-glass with a dead
spool, a session runs unrecorded.

Three things make that acceptable rather than a hole:

The path is hardcoded and not configurable by environment. The recorder runs as the unprivileged
login user, so a sentinel path that an env var could move would be an attacker's first move.

Detection is by presence, using `os.Stat`, so the sentinel does not have to be readable to be seen. A
present but empty or unreadable sentinel still engages, with a placeholder reason. Any stat error
reads as not engaged, so the failure direction is toward refusing sessions rather than allowing them.

Engaging it is a visible event, not a quiet one. The transition is audited as
`iam.machine.break_glass.engaged` and it pages (`src/api-gateway/internal/machines/handler.go:1536`).

⚠️ **Added 2026-09-04: that paging is conditional on reaching the gateway, and break-glass exists for
the case where reaching things is exactly what has stopped working.** The audit event and the page are
produced on the control plane. Root creates the sentinel on the host. If the spool is dead because the
network or the gateway is down — the ordinary reason a spool goes undurable — then the host engages
break-glass, sessions run unrecorded, and nothing pages until connectivity returns, if it returns.
Required: a durable local record of the engagement that the host must later reconcile with the control
plane, an alert on a reconciliation that arrives late or never arrives, and this paragraph saying out
loud that immediate paging is conditional on connectivity rather than implying it is not. Tracked as
TMSR-06.

And the thing worth saying plainly: creating that file needs root on the host. Somebody with root on
that host could equally just kill the recorder. Break-glass does not hand them a capability they did
not have. What it does is make them take the loud, recorded route to it instead of the quiet one.

## Assets

| Rank | Asset | What it costs you |
| --- | --- | --- |
| 1 | The gateway's recording signing key | Forge a transcript that verifies |
| 2 | The break-glass sentinel on a host | Run unrecorded on that host, loudly |
| 3 | The collector and its spool | Capture for every operator on the box |
| 4 | Stored recordings | Everything anyone typed, including things they should not have typed |
| 5 | Playback access in the console | Same disclosure, remotely, without touching the host |

## Adversaries

**A3, a legitimate user who would rather not be watched.** Has a shell, wants the transcript to be
absent, incomplete or wrong.

**A11, an unprivileged local user on a recorded host.** New here. Cannot read the spool, but shares
the machine and can reach the ingest socket.

**A4, an insider on the control plane.** Holds the signing key and the stored recordings.

## Trust boundaries

| From | To | Authentication | Status |
| --- | --- | --- | --- |
| Recorder, running as the operator | Collector, on the same host | `SO_PEERCRED` on a unix socket, sender only | **BUILT** |
| Collector | Gateway | Host mTLS | **BUILT** |
| Gateway | Stored recording | Gateway signs the document | **BUILT** |
| Console user | Playback | Policy, `recordings.read` gated on the recording feature | **BUILT** |

## Vectors and controls

### Getting out of being recorded

| Vector | Control | Status |
| --- | --- | --- |
| Start a session that is never captured | Refused at connect when the spool is unwritable and break-glass is not engaged. This is the core guarantee and it has a test whose name says so. | **BUILT** |
| Engage break-glass and run quietly | You need root, and you could have killed the recorder anyway. The transition is audited and pages. | **BUILT, and bounded** |
| Kill the recorder mid-session | Degrading your own capture is inherent and recorded as such. You are the operator, the recorder is your process. | **ACCEPTED** |
| Reach the machine by a path nobody wired a recorder to | ⚠️ Not modelled. SSH and sudo have recorders. `scp`, `sftp`, port forwarding, cron, systemd units, a local console login and anything else that gets a shell without going through those two are not described anywhere. | **NOT MODELLED** |

### Attacking somebody else's capture

| Vector | Control | Status |
| --- | --- | --- |
| Exhaust the collector so other operators lose capture | 🚨 The ingest socket is `0666` by design, so any local user can connect (`src/client-agent/internal/recorder/collector.go:73`). A global connection cap alone would be worse than useless, since one user could eat the whole budget, so there is a per-UID cap as well and that is the control that matters. | **BUILT** |
| Degrade a third party's capture anyway | ⚠️ Named as the real residue in the code and deliberately not papered over. When the collector is unreachable a recorder falls back to its own operator-deletable spool, and closing that needs a sender-side design decision rather than a socket option. | **OPEN, acknowledged** |
| Forge content into somebody else's transcript | The sender is authenticated by `SO_PEERCRED` and cannot be spoofed, so a document is attributable to the UID that sent it. The content itself is unauthenticated in transit, which is why the gateway is the only signer. | **PARTIAL, by design** |
| Forge content into your *own* transcript | ⭐ Added 2026-09-04, and it is the residue the row above leaves. `SO_PEERCRED` authenticates a kernel-reported UID. It does not authenticate a session, and it does not authenticate that the bytes were ever on anybody's terminal. Any process running as that UID — including one the operator started precisely for this — can submit a document that will be signed by the gateway and replayed as a session. The gateway's signature proves what the gateway received. It does not prove what appeared on the terminal, and this document has been treating those as the same claim. Required: a session nonce the server issues at connect and the recorder cannot choose, ordered chunks under that nonce, explicit start and end markers, durable acknowledgement of each chunk, and a stored status of `incomplete` when the end marker never arrives, so a truncated capture reads as truncated rather than as a short session. | **NOT MODELLED** |

### After capture

| Vector | Control | Status |
| --- | --- | --- |
| Alter a stored recording | The gateway signs each document over the transcript plus its binding. | **BUILT** |
| Delete recordings to hide a session | Not modelled here. Recordings follow whatever retention and off-box path the audit subsystem has, and that subsystem has one sink. See TMA2-01. | **NOT MODELLED** |
| Read recordings you should not | `recordings.list` and `recordings.read` are policy-gated and the auditor role is allowed. | **BUILT** |
| Terminal escapes or binary output make playback lie | Not modelled. A transcript is replayed, and a replay is a rendering. | **NOT MODELLED** |
| Secrets end up in the transcript | Not modelled, and it is a real one. A recorded session captures what was typed, including a password typed into the wrong prompt. Nothing redacts. | **NOT MODELLED** |

## What we do not defend against

- An operator degrading their own capture. They own the process. The control is that it is visible,
  not that it is impossible.
- Anyone holding the gateway signing key. They can produce a transcript that verifies.
- Recording making a session safe. It makes it reviewable. Those are different, and the review only
  happens if somebody looks.

## Still open

| ID | Item | Why it is still open |
| --- | --- | --- |
| TMSR-01 | Coverage of paths other than SSH and sudo | `scp`, `sftp`, port forwarding, cron, systemd units and console logins are undescribed. If any of them reaches a shell on a group that requires recording, the guarantee has a hole nobody has measured. |
| TMSR-02 | Third-party capture degradation | Acknowledged in the code as needing a sender-side design decision. |
| TMSR-03 | No redaction | Whatever is typed is captured, including things that should never be stored. |
| TMSR-04 | Retention and deletion of recordings | Undescribed, and they are bulkier and more sensitive than audit entries. |
| TMSR-06 | Break-glass paging depends on the connectivity break-glass exists for | ⭐ 2026-09-04. The page comes from the control plane and the sentinel is created on the host. During a network or gateway outage nothing pages, which is the case break-glass is for. |
| TMSR-07 | A transcript is bound to a UID and not to a session | ⭐ 2026-09-04. `SO_PEERCRED` proves which UID sent bytes. Any process under that UID can send any bytes. No session nonce, no ordering, no end marker, no incomplete status. |
| TMSR-05 | Playback rendering is untrusted input | A transcript replayed in a browser is attacker-influenced content. |

## Where this came from

`src/client-agent/internal/recorder/` throughout, in particular `ssh_command_audit.go` for the gate,
`ssh_recorder.go` for break-glass, `collector.go` for the socket and its caps, and `ingest_doc.go`
for who signs. Policy contract: `policies/segmentation/hostconfig.rego`. Break-glass side effects:
`src/api-gateway/internal/machines/handler.go`.
