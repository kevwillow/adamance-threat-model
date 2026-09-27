# Threat Model: session recording

> Status: **DRAFT, written 2026-09-01** against `b276339c`, corrected and extended 2026-09-04. Owner: project maintainer.
> External review: **2026-09-26.** Read in full by three reviewers; each finding that survived checking is added or corrected in place and dated 2026-09-26, and every corrected sentence quotes what it replaced. Not a whole-document re-measure.
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

⚠️ **Corrected 2026-09-26 (external review).** "That claim is real and it is enforced at connect time" is true of half of it. The connect gate enforces the unwritable-spool case; when the collector is unreachable, a recorder falls back to its own operator-deletable spool and the session proceeds (TMSRV-06, TMSR-02). The claim is the requirement and it stands. Durable capture means accepted by the collector or the gateway, not written to a local file. At connect time, an acceptance issued by the collector or the gateway proves the trusted capture path exists; the session nonce TMSRV-08 requires binds the session and its ordered chunks, and durable acknowledgements prove each chunk was stored.

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
| Console user | Playback | Policy, `recordings.read` gated on the recording feature | ⚠️ **AUTHORIZATION BUILT, PLAYBACK NOT.** Corrected 2026-09-05: this cell read **BUILT** while the build-status note at the top of this document says the player is placed on the console page and never loaded, so a recorded session cannot currently be watched. What is built is the authorization path in front of a viewer that does not exist. |

## Vectors and controls

### Getting out of being recorded

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMSRV-01 | Start a session that is never captured | Refused at connect when the spool is unwritable and break-glass is not engaged. This is the core guarantee and it has a test whose name says so. | **BUILT** |
| TMSRV-02 | Engage break-glass and run quietly | You need root, and you could have killed the recorder anyway. The transition is audited and pages. ⚠️ Corrected 2026-09-26 (external review): "pages" is conditional on reaching the gateway, which TMSR-06 records. Required: engagement is recorded locally at the moment it happens, in a root-owned record mirrored to syslog, reconciled to the control plane when connectivity returns and paged then, and a reconciliation that arrives late or never arrives is itself an alert. Status read **BUILT, and bounded** until 2026-09-26. | **PARTIAL** |
| TMSRV-03 | Kill the recorder mid-session | ⚠️ **Corrected 2026-09-05. This read "Degrading your own capture is inherent and recorded as such." The first half is true and the second half is not.** Degrading your own capture is inherent — you are the operator and the recorder is your process. It is *not* recorded as such: this document's own TMSR-07 establishes that there is no end marker and no `incomplete` status, so a killed recorder produces a transcript that is indistinguishable from a short session. "Recorded as such" was the sentence that made the acceptance sound bounded, and nothing implements it. The acceptance stands for the killing; it does not stand for the recording of the killing. | **ACCEPTED for the act, NOT MODELLED for the evidence** |
| TMSRV-04 | Reach the machine by a path nobody wired a recorder to | ⚠️ Not modelled. SSH and sudo have recorders. `scp`, `sftp`, port forwarding, cron, systemd units, a local console login and anything else that gets a shell without going through those two are not described anywhere. | **NOT MODELLED** |
| TMSRV-14 | Break-glass stays engaged long after the emergency that justified it | ⭐ Added 2026-09-26 (external review). Break-glass is a bounded exception, not a mode. Each engagement carries a stated scope and a maximum duration after which the host disengages it on its own; renewing it is a new, recorded engagement; and every engagement ends in an after-action review recorded against it. | **NOT MEASURED** |

### Attacking somebody else's capture

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMSRV-05 | Exhaust the collector so other operators lose capture | 🚨 The ingest socket is `0666` by design, so any local user can connect (`src/client-agent/internal/recorder/collector.go:73`). A global connection cap alone would be worse than useless, since one user could eat the whole budget, so there is a per-UID cap as well and that is the control that matters. | **BUILT** |
| TMSRV-06 | Degrade a third party's capture anyway | ⚠️ Named as the real residue in the code and deliberately not papered over. When the collector is unreachable a recorder falls back to its own operator-deletable spool, and closing that needs a sender-side design decision rather than a socket option. ⭐ Required control stated 2026-09-26 (external review): when the collector is unreachable the session is refused unless break-glass is engaged, and there is no operator-writable fallback spool. Where a local buffer exists it is root-owned, append-only for the login user and drained by the collector, so a starved sender cannot delete its own capture. | **OPEN, acknowledged** |
| TMSRV-07 | Forge content into somebody else's transcript | The sender is authenticated by `SO_PEERCRED` and cannot be spoofed, so a document is attributable to the UID that sent it. The content itself is unauthenticated in transit, which is why the gateway is the only signer. | **PARTIAL, by design** |
| TMSRV-08 | Forge content into your *own* transcript | ⭐ Added 2026-09-04, and it is the residue the row above leaves. `SO_PEERCRED` authenticates a kernel-reported UID. It does not authenticate a session, and it does not authenticate that the bytes were ever on anybody's terminal. Any process running as that UID — including one the operator started precisely for this — can submit a document that will be signed by the gateway and replayed as a session. The gateway's signature proves what the gateway received. It does not prove what appeared on the terminal, and this document has been treating those as the same claim. Required: a session nonce the server issues at connect and the recorder cannot choose, ordered chunks under that nonce, explicit start and end markers, durable acknowledgement of each chunk, and a stored status of `incomplete` when the end marker never arrives, so a truncated capture reads as truncated rather than as a short session. ⭐ Strengthened 2026-09-26 (external review): a nonce, ordered chunks and end markers stop confusion and truncation, and do not stop a process under the same UID inventing content in the right order. For a session claimed as authentically captured, a capture component outside the login user's writable and signalable process boundary observes the session's data path and authenticates its output to the collector, so an arbitrary submission from another process under that UID cannot become authenticated capture. Losing the trusted capture path is visible and invokes the required-recording policy. This does not claim resistance to root on the host. | **NOT MODELLED** |

### After capture

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMSRV-09 | Alter a stored recording | The gateway signs each document over the transcript plus its binding. | **BUILT** |
| TMSRV-10 | Delete recordings to hide a session | Not modelled here. Recordings follow whatever retention and off-box path the audit subsystem has, and that subsystem has one sink. See TMA2-01. ⭐ Required control, added 2026-09-26 (external review): this row said recordings follow the audit subsystem's path, and TMS-12's 2026-09-22 re-measure found they land in a separate signed store and never enter the chain. Required: the digest of every recording document becomes a chain entry at ingest, so a deleted or altered recording disagrees with the chain. Recordings are append-only until retention expires for every credential the control plane holds, deletion before expiry is a gated, dual-controlled, audited operation that leaves a tombstone, and off-box preservation follows TMA2-06. Status read **NOT MODELLED** until 2026-09-26. | **NOT_BUILT** |
| TMSRV-11 | Read recordings you should not | `recordings.list` and `recordings.read` are policy-gated and the auditor role is allowed. ⭐ Extended 2026-09-26 (external review), measured at `27679898d`: every read, replay and export emits a chained audit entry naming the reader, the recording and the stated reason, as the main threat model requires, and export is its own gated operation. Today a read writes a log line (`recordings.get`, `src/api-gateway/internal/handlers/recordings/handlers.go:614`), not a chain entry, and no export operation exists. Status read **BUILT** until 2026-09-26. | **PARTIAL** |
| TMSRV-12 | Terminal escapes or binary output make playback lie | Not modelled. A transcript is replayed, and a replay is a rendering. | **NOT MODELLED** |
| TMSRV-13 | Secrets end up in the transcript | Not modelled, and it is a real one. A recorded session captures what was typed, including a password typed into the wrong prompt. Nothing redacts. | **NOT MODELLED** |

## What we do not defend against

- An operator degrading their own capture. They own the process. The control is that it is visible,
  not that it is impossible.
- Anyone holding the gateway signing key. They can produce a transcript that verifies.
- Recording making a session safe. It makes it reviewable. Those are different, and the review only
  happens if somebody looks.

## Still open

| ID | Item | Why it is still open | Status |
| --- | --- | --- | --- |
| TMSR-01 | Coverage of paths other than SSH and sudo | `scp`, `sftp`, port forwarding, cron, systemd units and console logins are undescribed. If any of them reaches a shell on a group that requires recording, the guarantee has a hole nobody has measured. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** No server-side enforcement binds a session to a recorder. ⚠️ Two statements from an earlier measurement are corrected: the TCP-forwarding denial is the directive `AllowTcpForwarding no` at `sshd.go:179` (with `PermitOpen none` at `:180`), not the comment at `:171`; and the claim that no scp/sftp handling exists is FALSE — `ssh_recorder.go:545` branches on `SSH_ORIGINAL_COMMAND` and dispatches to `runNonInteractive` (`:584`), which records the command line and exit status as frames while deliberately leaving stdio byte-transparent. ⇒ For scp the CONTENT is un-captured **by design**, not uncovered by omission, which is a different and smaller gap than the row implied. Evidence: `src/client-agent/internal/hostconfig/sshd.go:179` · `src/client-agent/internal/recorder/ssh_recorder.go:545` · `src/client-agent/internal/recorder/ssh_recorder.go:584` | **NOT_BUILT** |
| TMSR-02 | Third-party capture degradation | Acknowledged in the code as needing a sender-side design decision. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The sender-side design decision the row waits on has not been taken. collector.go:400-405 still states the residue verbatim — a starved sender's recorder "writes to its own operator-deletable spool", degrading a THIRD PARTY's capture is "the real residue", and closing it "needs a sender-side decision about what a recorder does when the collector is unreachable... Tracked as such; do not paper over it here." The connect gate confirms nothing changed on the sender side: decideSSHSessionGate (ssh_command_audit.go:155-175) refuses only when the recorder's own spool errors, so an unreachable collector with a writable fallback spool lets the session proceed. The per-uid connection cap (collector.go:95 defaultMaxConnsPerUID = 8, enforced at :207) bounds socket exhaustion — that is TMSRV-05, already marked BUILT — and does not touch this row. MISSING: any sender-side behaviour change, and any decision record accepting the residue. Evidence: `src/client-agent/internal/recorder/collector.go:399-405` · `src/client-agent/internal/recorder/collector.go:84-89` · `src/client-agent/internal/recorder/collector.go:95` · `src/client-agent/internal/recorder/collector.go:207` · `src/client-agent/internal/recorder/ssh_command_audit.go:155` | **NOT_BUILT** |
| TMSR-03 | No redaction | Whatever is typed is captured, including things that should never be stored. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** No redaction touches a session transcript. A concept search (redact/scrub/sanitiz) scoped to src/client-agent/internal/recorder, policies/recordings and web/admin-ui/src/pages/SessionRecordings.tsx returns nothing. The hits in the recordings package are sanitizeAdminMap (admin_ui.go:221 comment, :269 definition, called at :152 on act.RequestBody) — that redacts password/token/secret fields out of admin-UI mutating-action REQUEST BODIES before they are signed into the recordings index. It is a different document type on a different ingest path and never sees keystrokes. An open gap confirms the reading: "redaction is not built". MISSING: any redaction, masking or pattern suppression on captured terminal input/output, and any recorded decision to accept the exposure. Evidence: `src/api-gateway/internal/handlers/recordings/admin_ui.go:152` · `src/api-gateway/internal/handlers/recordings/admin_ui.go:221-229` · `src/api-gateway/internal/handlers/recordings/admin_ui.go:269-278` | **NOT_BUILT** |
| TMSR-04 | Retention and deletion of recordings | Undescribed, and they are bulkier and more sensitive than audit entries. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** HOLDS: a 90-day ISM policy named adamance-sessions-retention is installed against the session indices at boot (main.go:2617), and an explicit rejection of that policy by the indexer now refuses to start (main.go:2610-2612, ErrISMPolicyRejected -> logger.Error + exit). MISSING, both clauses of the row: (1) retention is still optional in practice — with no admin indexer credential configured the gateway warns "session indices will grow unbounded until it is installed out-of-band" and boots anyway (main.go:2606), and any non-rejection install error is logged and boot continues (main.go:2614); (2) deletion and export are unmodelled and unauditable — a search for "recordings.export", "recordings.delete", "recordings.purge" across src/, policies/ and the OpenAPI spec returns zero matches, against recordings.list and recordings.read which are policy-gated at policies/api/authz.rego:1679 and :1690. NOTE: the cited line numbers (2552, 2563) have drifted to 2606 and 2617. Evidence: `src/api-gateway/cmd/server/main.go:2606` · `src/api-gateway/cmd/server/main.go:2609-2618` · `policies/api/authz.rego:1679` · `policies/api/authz.rego:1690` | **PARTIAL** |
| TMSR-06 | Break-glass paging depends on the connectivity break-glass exists for | ⭐ 2026-09-04. The page comes from the control plane and the sentinel is created on the host. During a network or gateway outage nothing pages, which is the case break-glass is for. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** ⚠️ An earlier measurement's headline residual — "no durable local record of WHEN the host engaged" — is REFUTED. Every break-glass session writes a timestamped record on two independent channels: `ssh_recorder.go:519-535` builds `breakGlassRecord{Event, Time: RFC3339, User, Host, Reason, PreflightErr}` and sends it to syslog AUTHPRIV (which the unprivileged login user cannot rewrite) and to `/var/log/ssh-recorder-breakglass.log`; the sudo half does the same at `sudo_recorder_main.go:160-173`; and the gateway stores `break_glass_since`. The accurate residue is narrower: (a) engagement that produces NO session leaves no local record, because the sentinel's creation time is never captured, and (b) nothing ever ships or reconciles that local log against the control plane. Evidence: `src/client-agent/internal/recorder/ssh_recorder.go:519` · `src/client-agent/cmd/sudo-recorder/sudo_recorder_main.go:160` · `src/api-gateway/internal/handlers/recordings/handler.go:1803` Tracked as an open gap: break-glass is host-side by construction. | **PARTIAL** |
| TMSR-07 | A transcript is bound to a UID and not to a session | ⭐ 2026-09-04. `SO_PEERCRED` proves which UID sent bytes. Any process under that UID can send any bytes. No session nonce, no ordering, no end marker, no incomplete status. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** ⚠️ Two of the four absences an earlier measurement asserted are REFUTED — the search terms missed the concept. Chunk ordering and an end marker DO exist: `IngestDoc` carries `Seq` and `DocType "segment"/"meta"` (`ingest_doc.go:22-23`), and `SSHRecorder.Finalise()` spools a terminal `meta` document with an RFC3339 `EndTime`. The gateway knows about it: `selectSessionMeta` returns the terminal meta "falling back to the first hit when no meta doc is present (a segment-only partial session)". ⇒ The corrected statement still supports NOT_BUILT: ordering and the end marker are RECORDER-CHOSEN and unauthenticated — nothing server-issued constrains them — and the gateway SILENTLY DOWNGRADES to `hits[0]` when the terminal doc is missing instead of recording the session as incomplete. Evidence: `src/client-agent/internal/recorder/ingest_doc.go:22` · `src/client-agent/internal/recorder/ssh_recorder.go:286` · `src/api-gateway/internal/handlers/recordings/handlers.go:411` No open gap tracks the silent-downgrade behaviour specifically yet. | **NOT_BUILT** |
| TMSR-05 | Playback rendering is untrusted input | A transcript replayed in a browser is attacker-influenced content. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** No rendering control exists, and no transcript is rendered today. SessionRecordings.tsx:453 places <asciinema-player src={recording.recording_signed}> behind a `// @ts-ignore`, but asciinema appears in neither web/admin-ui/package.json nor web/admin-ui/index.html (grep -i asciinema -> exit 1 on both) and nothing registers the custom element, so the SSH branch renders an undefined element and never paints a transcript — this is the missing-player gap. The non-SSH branch renders JSON.stringify(recording.recording_signed, null, 2) inside a React <pre> (SessionRecordings.tsx:521-525), which React escapes; dangerouslySetInnerHTML has zero occurrences anywhere under web/. MISSING: any terminal-escape or control-character handling, any stated rendering-trust boundary, and any decision record. The threat is not reachable today only because the player is absent — closing that gap makes it live with nothing in place. Evidence: `web/admin-ui/src/pages/SessionRecordings.tsx:440` · `web/admin-ui/src/pages/SessionRecordings.tsx:451-461` · `web/admin-ui/src/pages/SessionRecordings.tsx:521-525` | **NOT_BUILT** |

## Where this came from

`src/client-agent/internal/recorder/` throughout, in particular `ssh_command_audit.go` for the gate,
`ssh_recorder.go` for break-glass, `collector.go` for the socket and its caps, and `ingest_doc.go`
for who signs. Policy contract: `policies/segmentation/hostconfig.rego`. Break-glass side effects:
`src/api-gateway/internal/machines/handler.go`.
