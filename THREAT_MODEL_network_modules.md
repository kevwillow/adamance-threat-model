# Threat Model: the network modules, VPN, RADIUS and DNS

> Status: **DRAFT, written 2026-09-01** against `b276339c`, extended 2026-09-04. Owner: project maintainer.
> External review: **2026-09-26.** Read in full by three reviewers; each finding that survived checking is added or corrected in place and dated 2026-09-26, and every corrected sentence quotes what it replaced. Not a whole-document re-measure.
> Companion to [`THREAT_MODEL.md`](THREAT_MODEL.md). These three are optional modules, and the
> main threat model refers to them only in two cross-cutting rows (revocation convergence and credentialed egress) and models none of them. ⚠️ Corrected 2026-09-26: this read "the main threat model does not mention any of them", which stopped being true on 2026-09-04.
>
> ⚠️ **Build status up front.** RADIUS has real code and the most interesting security work in this
> document. DNS filtering has a built control-plane half and **no resolver process at all**, so an
> operator can save a filtering policy that filters nothing: the shipped blocklist catalogue is
> literally empty (`src/modules/dns/blocklist/catalogue.go:29`, `func Shipped() Catalogue { return
> Catalogue{} }`). Tracked as open gaps.

---

## Why these three sit together

Each one lets something that is not a managed Linux host authenticate against adamance, or lets
adamance decide something for a device it does not manage. A switch. A wireless controller. A phone
on the guest network. A laptop asking for a name.

That is a different shape from the rest of the product. Everywhere else, the thing on the other end
holds a certificate we issued and runs an agent we wrote. Here it holds a shared secret, or it just
sends a UDP packet and trusts the answer.

## RADIUS

### The control worth reading

Every RADIUS client row carries a `secret_ref`, and the shared secret gets rendered into a
`clients.conf` that is then shipped to a host. The obvious implementation is to hand `secret_ref` to
the generic secrets store and let it resolve.

That would have been a confused deputy, and the code says so plainly
(`src/api-gateway/internal/radiussecrets/radiussecrets.go`). `secrets.Store.Get` resolves `path#field`
against the KV mount and also `file:`, `env:` and bare filesystem paths, and the gateway's
highest-value secrets are configured as exactly those forms. So anyone who could create a RADIUS
client could have named `file:/run/secrets/session_signing_key` and had the session signing key
rendered into a config file delivered to a machine they control.

The rule that closes it: **`secret_ref` is a name, never a path.** The package owns the name to
location mapping, the prefix is a compile-time constant, and the name is re-validated in the package
rather than trusted from the row, because the database is not a trust boundary and a row can predate
a tightened validator or arrive from a direct SQL writer.

⭐ That last clause is the part most implementations get wrong. Validating on write and trusting on
read is only correct while writes are the only way rows appear.

### RADIUS vectors

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMNV-01 | A client row names a path and exfiltrates another secret | `secret_ref` is a name, re-validated at resolution. | **BUILT** |
| TMNV-02 | Shared secret stolen from a switch or an AP | Not modelled. A RADIUS shared secret sits in the config of a device you often do not control, and the protocol's own protection of it is weak. Rotation is undescribed. | **NOT MODELLED** |
| TMNV-03 | RADIUS over plain UDP on an untrusted segment | ⭐ Required control written 2026-09-04, where this row previously said only "not modelled". RADIUS over TLS (RadSec) or an equivalent tunnel is required on any segment adamance does not control. Where legacy UDP or TCP transport remains, `Message-Authenticator` is mandatory on every packet in both directions and a packet without it is dropped: without it the MD5-based construction leaves requests forgeable and replayable, which is the subject of RFC 9765. ⚠️ **Flagged 2026-09-05, not yet corrected. This continued "and RADIUS/1.1 removes that protection entirely rather than repairing it", and at least one reviewer reads that as backwards** — RADIUS/1.1 retires the MD5-based construction because it mandates secure transport instead, which is replacement rather than removal of protection. Three of four reviewers could not settle it from the text. It is left standing with this note rather than swapped for another unchecked sentence, and it needs somebody with the RFCs open. Separately flagged the same day: a reviewer reported inbound enforcement built against a NOT BUILT status, and the claim was held until it came with a file and a line, which is this project's rule for flipping a status. It has one now: the status below cites it and reads PARTIAL. The permitted EAP methods are stated rather than left to whatever the server ships with. | **PARTIAL**: `Message-Authenticator` rendered into every client stanza (`src/modules/radius/radiusconf/clientsconf.go:113`) with a guard test citing CVE-2024-3596 (`src/modules/radius/radiusconf/clientsconf_test.go:34`); RadSec-or-tunnel and the stated permitted-EAP-methods remain UNBUILT (no RadSec code, no stated EAP-method list). Requirement stands. |
| — | Any enrolled host reads every RADIUS shared secret | 🔴 **NOT HELD, measured 2026-09-04.** The route that serves RADIUS client configuration authenticates the host certificate and never asks whether that host is still enrolled, and it is one of four routes with that shape. So a revoked host, or any enrolled host outside the scope anyone intended, fetches every shared secret in the deployment. The `secret_ref` rule above stops a client row naming somebody else's secret; it does nothing about who may ask for the rendered file. Required: enrollment status checked at use, and the configuration scoped to the RADIUS clients the requesting host actually serves. See TM-40 in the main threat model. ⚠️ Re-measured 2026-09-27 at `dd2185205`: half of this is now held. The host-lifecycle gate refuses a revoked host on every host-mTLS route (TM-40), and the route serves the file only to a host registered as an enabled RADIUS server, auditing every refusal (TMNV-15, `src/api-gateway/internal/handlers/radius/clientsconfig.go:207`). The other half is not: every enabled RADIUS server receives every enabled client and its secret (`ListEnabledClients`, `:242`), not only the clients it serves. Status read **OPEN** until 2026-09-27. | **PARTIAL** |
| TMNV-04 | Offline attack on the RADIUS authenticator | Not modelled. This is the well-known weakness of the older protocol modes and it depends on which EAP methods are permitted, which nothing records. | **NOT MODELLED** |
| TMNV-05 | A device is deleted in the console but keeps authenticating | Convergence and heartbeat handlers exist so drift is at least observable (`src/api-gateway/internal/handlers/radius/heartbeat.go`). Whether removal is enforced promptly is undescribed. | **PARTIAL** |
| TMNV-06 | Client config shipped to the wrong host | ⚠️ Unlike the directory bind credential in `adsecrets`, a RADIUS secret is deliberately **not** bound to one destination endpoint, because a RADIUS client legitimately has more than one. That is a reasoned decision, and it does mean the binding control that exists elsewhere is absent here. | **ACCEPTED, by design** |
| TMNV-15 | An enrolled host that is not a RADIUS server pulls the rendered `clients.conf`, which carries every shared secret | ⭐ Added 2026-09-26 (external review). The route is authorised against the object, not only the certificate: only a host registered as an enabled RADIUS server receives the file, any other enrolled host is refused, and the refusal is audited with the caller's name. Measured at `27679898d`: the handler looks the calling certificate's FQDN up among enabled RADIUS servers before rendering anything (`src/api-gateway/internal/handlers/radius/clientsconfig.go:207`, `LookupEnabled`), and the policy rule says in its own comment that it is not the boundary (`policies/api/authz.rego:132-137`), and both refusal paths emit an audit event naming the calling host (`emitRefusal` at `:530`, called at `:216` and `:222`). | **BUILT** |

## DNS

### Say the state plainly

The operator can store which domains they want blocked, and there is a status page. There is no name
lookup service in the tree, no `miekg/dns`, no CoreDNS, and the shipped catalogue of blocklist
sources returns an empty struct. So today no device is protected and no lookup is filtered.

The public site presents a network-wide DNS sinkhole with content filtering and locked-down Kids
accounts as a v1 feature. That is the single largest distance between a promise and a running
process anywhere in the product.

### DNS vectors, written for when the resolver exists

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMNV-07 | A device ignores the resolver and asks 8.8.8.8 | none. Filtering by resolver is advisory unless something forces traffic through it, and nothing describes that enforcement. ⭐ Required control, added 2026-09-26 (external review): on a managed host the agent's firewall ruleset redirects outbound DNS on port 53 to the adamance resolver and drops port 53 to anything else. For an unmanaged device the console states whether enforcement happens at the network (the operator's router redirects) or is advisory, and never shows an advisory device as filtered. Status read **NOT MODELLED** until 2026-09-26; there is no resolver yet (TMN-01). | **NOT_BUILT** |
| TMNV-08 | DNS over HTTPS or TLS bypasses the sinkhole entirely | none, and this is the one that decides whether the feature means anything. A modern browser can be talking to its own resolver over 443 without asking the system at all. ⭐ Required control, added 2026-09-26 (external review): on a managed host the same ruleset blocks outbound 853 and the published DNS-over-HTTPS resolver addresses, and the resolver answers the canary domains browsers check before enabling DNS-over-HTTPS, so cooperating clients switch it off. Terminating DNS-over-HTTPS or DNS-over-TLS is a non-goal of the DNS design, and the console says so. Status read **NOT MODELLED** until 2026-09-26; there is no resolver yet (TMN-01). | **NOT_BUILT** |
| TMNV-09 | A blocklist source is compromised and blocks or redirects something it should not | The catalogue is described as the reviewed set of sources adamance is willing to fetch, which is the right shape. It is empty, so the property is untested. | **DESIGNED** |
| TMNV-10 | Sinkhole answers are themselves a channel | Not modelled. A sinkhole returns an answer, and what it returns is a decision. | **NOT MODELLED** |
| TMNV-11 | Kids accounts are bypassed by changing a device's resolver | Not modelled, and on a device the child controls this is the obvious first move. ⭐ Required control, added 2026-09-26 (external review): a Kids account's devices are enforced only where TMNV-07 holds. A device that cannot be enforced is labelled advisory beside the account, and the account is never shown as protected while any of its devices is advisory. Status read **NOT MODELLED** until 2026-09-26; there is no resolver yet (TMN-01). | **NOT_BUILT** |

## VPN

The design covers client profile issuance. The main threat model already leans on the VPN perimeter
heavily: SCOPE-10 makes v1 private and VPN-only, and the initial-access row treats "bind to the
private network or VPN" as the control that keeps the admin console off the public internet.

⚠️ That is worth stating as a dependency rather than leaving implicit. **A large part of the product's
v1 security posture is carried by a network boundary the product does not itself provide.** If an
operator's mesh or VPN is misconfigured, several rows in the main threat model quietly stop holding,
and nothing in adamance would notice or say so.

| ID | Vector | Control | Status |
| --- | --- | --- | --- |
| TMNV-12 | Profile issued to the wrong person | Profiles are issued through the same authenticated console as everything else. | **PARTIAL** |
| TMNV-13 | A profile outlives the person | Not modelled separately from account lifecycle. | **NOT MODELLED** |
| TMNV-14 | The perimeter the threat model assumes is not actually there | Nothing checks. No posture check asks whether the console is reachable from outside. | **NOT MODELLED** |

## What we do not defend against

- A device we do not manage, behaving badly on a network we do not run. These modules authenticate
  and answer. They do not police.
- An operator who turns a module on and assumes it does more than it does. That is what the build
  status banner at the top of this document is for, and it is why the DNS section says the resolver
  does not exist rather than describing what it would do.

## Still open

| ID | Item | Why it is still open | Status |
| --- | --- | --- | --- |
| TMN-01 | No resolver exists | A filtering policy can be saved and filters nothing. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** No resolver exists anywhere in the tree, so a saved filtering policy filters nothing — the row is accurate as written. The DNS module's own package doc states it: "This package lays a schema and NOTHING ELSE. No resolver is installed, no daemon is supervised, no lookup is filtered and no blocklist is fetched" (src/modules/dns/store.go:7-10). The shipped blocklist catalogue is literally empty — `func Shipped() Catalogue { return Catalogue{} }` (catalogue.go:29). A control-plane half does exist and is real (src/modules/dns/policy/, src/modules/dns/state/, src/api-gateway/internal/handlers/dns/), which is why the honest verdict is about the resolver, not about the module. A 2026-09-10 re-measurement at aec111da printed 0 resolver dependencies in any go.mod/go.sum (control: 17 for jackc/pgx), 0 name-serving code (control: 7 real ListenAndServe call sites), 0 DNS server in deploy/ (control: 41 postgres hits). NOT checked: that walk was not re-run; the two code facts it rests on were confirmed directly. Evidence: `src/modules/dns/store.go:7` · `src/modules/dns/blocklist/catalogue.go:29` The primary open gap: no name-lookup service exists. | **NOT_BUILT** |
| TMN-02 | Encrypted DNS bypass is undescribed | Decides whether the feature is meaningful at all once it exists. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The row's word is "undescribed", and that clause no longer holds: The DNS design states the bypass plainly — "Any application using DNS-over-HTTPS bypasses it entirely, and a device can hardcode its own resolver" — and bounds the permitted claim to "refuse to answer lookups from cooperating clients". The design's non-goals then record the decision not to solve it: "DoH/DoT termination, in either direction. The bypass is stated, not solved", and a later section calls it one of the two ceilings on the feature. What is still missing: (a) the threat model's own vector row TMNV-08 still reads "none ... NOT MODELLED" at line 77, so this document never absorbed the design's decision; (b) nothing in the tree detects, blocks or reports encrypted-DNS bypass — a concept grep for dns-over-https / dns-over-tls / encrypted dns / doh across src/, web/ and policies/ returned only unrelated `sudoHook` substring matches, zero real hits. It is moot in practice while TMN-01 stands. I stopped short of ACCEPTED because the recorded non-goal covers only DoH/DoT *termination*, not the broader "force traffic through the resolver" half that TMNV-07 also leaves at none. | **PARTIAL** |
| TMN-03 | RADIUS shared-secret lifecycle | Storage on the device, rotation, and revocation are all undescribed. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Two of the three named clauses now have built, wired, policy-gated mechanisms, so "all undescribed" is stale. ROTATION: `PUT /api/v1/radius/clients/{id}/secret` is mounted at main.go:4623 and gated as `radius.client.enroll_secret` at authz.rego:233-234; it lands on radiussecrets.Enroller.Enroll, whose doc says "It overwrites any existing secret for the ref, which is what rotation is" (radiussecrets.go:201-202). REVOCATION: `PUT .../enabled` and `DELETE .../{id}` are mounted at main.go:4621-4622 and gated at authz.rego:210-226, with audit events `iam.radius.client.enabled_changed` / `.deleted` / `.secret_enrolled` (operator.go:88-90), and an all-revoked set renders as a legal empty config so the last client CAN be revoked (clientsconf.go:49-52). WHAT IS MISSING: (1) destruction — the shared secrets store exposes only Get and Put on both backends (secrets.go:145,176; openbao.go:201,253), so a deleted client's secret stays in the vault forever and the next client under the same ref inherits it — that is the destruction gap, and its evidence was confirmed independently with the same grep shape (Get/Put found as the positive control, Delete/Destroy/Remove/Purge/Revoke absent); (2) no rotation cadence, expiry or reminder exists anywhere — the only other rotation prose in the package is configmac.go:117, "THERE IS NO ROTATION SURFACE YET", which is about the config-MAC key, not the client secret; (3) storage on the device itself is unaddressed and this document already says so at TMNV-02 (line 54). Evidence: `src/api-gateway/cmd/server/main.go:4621` · `src/api-gateway/cmd/server/main.go:4623` · `policies/api/authz.rego:233` · `src/api-gateway/internal/radiussecrets/radiussecrets.go:201` · `src/api-gateway/internal/handlers/radius/operator.go:88` · `src/modules/radius/radiusconf/clientsconf.go:49` | **PARTIAL** |
| TMN-04 | RADIUS transport posture | ⭐ Updated 2026-09-04: the requirement is now stated — RadSec on untrusted segments, `Message-Authenticator` mandatory wherever legacy transport remains, permitted EAP methods written down. None of it is built or configured, and nothing refuses a client that omits it. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** The row's sentence "None of it is built or configured" is STALE and is the overclaim-in-reverse to correct here. One of the three stated clauses IS built: every rendered client stanza carries `require_message_authenticator = yes` (clientsconf.go:113, read directly — the Fprintf format string), with a guard test that names CVE-2024-3596 / the BlastRADIUS forged-Access-Accept class (clientsconf_test.go:30-38). The other two remain unbuilt: a concept grep for radsec / "radius over tls" / port 2083 across src/, policies/, deploy/, configs/ hit ONLY prose (this file's own TMNV-03) — zero code; and a grep for eap-tls / eap-ttls / peap / eap method across src/, deploy/, configs/, policies/ returned 3 hits, all Go comments about identity forms in the posture path (posture.go:306, postureconf.go:75, posture_live_test.go:510), none a stated permitted-method list. The vector row TMNV-03 at line 55 already records exactly this split as PARTIAL, so the still-open register at line 114 simply lags its own vector table by one pass. NOT checked: whether a running FreeRADIUS actually drops a packet lacking Message-Authenticator — the directive is rendered into config and enforcement is the daemon's; The live-supervisor test body that mentions it was not read. Evidence: `src/modules/radius/radiusconf/clientsconf.go:113` · `src/modules/radius/radiusconf/clientsconf_test.go:34` | **PARTIAL** |
| TMN-05 | The VPN perimeter is an unverified assumption | Several main-threat-model rows depend on it and nothing checks it holds. ⚠️ **Re-measured 2026-09-21 at `857f6f0e`.** Nothing in the tree verifies that the private/VPN perimeter the main threat model relies on is actually there. The dependency is real and explicit: THREAT_MODEL.md:197 and :343 state the required control as "V1 is private/VPN-only (Locked) ... no public internet exposure", and :89-90 bounds FreeIPA LDAPS/Kerberos exposure by the same perimeter. The only surface that touches the question is a SELF-DECLARED hardening-wizard question — `internet_facing`, "Is this deployment reachable from the internet?" (wizard.go:91-97) — whose answer shifts the hardening ladder from what the operator typed and measures nothing. A concept grep for internet-facing / reachable-from-outside / externally-reachable / publicly-exposed / exposure-check / wan-exposure across src/, web/, policies/ and deploy/ produced no reachability probe, no boot guard on a public bind for the API, and no posture check; the loopback defaults that do exist are for the metrics listener (config.go:922) and for the setup edge, which are bind choices reported as their own defects, not checks that the perimeter holds. NOT checked: the runbooks, deploy/setup/install.sh prose, and scripts/ — an operator-facing instruction to verify the perimeter could exist there; it still would not be the tree checking. Marked inferred because the verdict rests on an absence across a large tree. Evidence: `src/api-gateway/internal/settingsregistry/wizard.go:91` | **NOT_BUILT** |

## Where this came from

Code: `src/api-gateway/internal/radiussecrets/radiussecrets.go`, `src/modules/dns/blocklist/catalogue.go`,
`src/api-gateway/internal/handlers/dns/handler.go`.
