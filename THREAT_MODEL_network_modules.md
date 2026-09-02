# Threat Model: the network modules, VPN, RADIUS and DNS

> Status: **DRAFT, first pass, written 2026-09-01** against `b276339c`. Owner: project maintainer.
> Companion to [`docs/THREAT_MODEL.md`](THREAT_MODEL.md). These three are optional modules, and the
> main threat model does not mention any of them.
>
> ⚠️ **Build status up front.** RADIUS has real code and the most interesting security work in this
> document. DNS filtering has a built control-plane half and **no resolver process at all**, so an
> operator can save a filtering policy that filters nothing: the shipped blocklist catalogue is
> literally empty (`src/modules/dns/blocklist/catalogue.go:29`, `func Shipped() Catalogue { return
> Catalogue{} }`). Tracked as G02 and G18 in [`docs/V1_GAP_REGISTRY.md`](V1_GAP_REGISTRY.md).

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

| Vector | Control | Status |
| --- | --- | --- |
| A client row names a path and exfiltrates another secret | `secret_ref` is a name, re-validated at resolution. | **BUILT** |
| Shared secret stolen from a switch or an AP | Not modelled. A RADIUS shared secret sits in the config of a device you often do not control, and the protocol's own protection of it is weak. Rotation is undescribed. | **NOT MODELLED** |
| RADIUS over plain UDP on an untrusted segment | Not modelled. Nothing states whether RadSec or a tunnel is required, or what happens on a flat network. | **NOT MODELLED** |
| Offline attack on the RADIUS authenticator | Not modelled. This is the well-known weakness of the older protocol modes and it depends on which EAP methods are permitted, which nothing records. | **NOT MODELLED** |
| A device is deleted in the console but keeps authenticating | Convergence and heartbeat handlers exist so drift is at least observable (`src/api-gateway/internal/handlers/radius/heartbeat.go`). Whether removal is enforced promptly is undescribed. | **PARTIAL** |
| Client config shipped to the wrong host | ⚠️ Unlike the directory bind credential in `adsecrets`, a RADIUS secret is deliberately **not** bound to one destination endpoint, because a RADIUS client legitimately has more than one. That is a reasoned decision, and it does mean the binding control that exists elsewhere is absent here. | **ACCEPTED, by design** |

## DNS

### Say the state plainly

The operator can store which domains they want blocked, and there is a status page. There is no name
lookup service in the tree, no `miekg/dns`, no CoreDNS, and the shipped catalogue of blocklist
sources returns an empty struct. So today no device is protected and no lookup is filtered.

The public site presents a network-wide DNS sinkhole with content filtering and locked-down Kids
accounts as a v1 feature. That is the single largest distance between a promise and a running
process anywhere in the product.

### DNS vectors, written for when the resolver exists

| Vector | Control | Status |
| --- | --- | --- |
| A device ignores the resolver and asks 8.8.8.8 | none. Filtering by resolver is advisory unless something forces traffic through it, and nothing describes that enforcement. | **NOT MODELLED** |
| DNS over HTTPS or TLS bypasses the sinkhole entirely | none, and this is the one that decides whether the feature means anything. A modern browser can be talking to its own resolver over 443 without asking the system at all. | **NOT MODELLED** |
| A blocklist source is compromised and blocks or redirects something it should not | The catalogue is described as the reviewed set of sources adamance is willing to fetch, which is the right shape. It is empty, so the property is untested. | **DESIGNED** |
| Sinkhole answers are themselves a channel | Not modelled. A sinkhole returns an answer, and what it returns is a decision. | **NOT MODELLED** |
| Kids accounts are bypassed by changing a device's resolver | Not modelled, and on a device the child controls this is the obvious first move. | **NOT MODELLED** |

## VPN

The design covers client profile issuance. The main threat model already leans on the VPN perimeter
heavily: SCOPE-10 makes v1 private and VPN-only, and the initial-access row treats "bind to the
private network or VPN" as the control that keeps the admin console off the public internet.

⚠️ That is worth stating as a dependency rather than leaving implicit. **A large part of the product's
v1 security posture is carried by a network boundary the product does not itself provide.** If an
operator's mesh or VPN is misconfigured, several rows in the main threat model quietly stop holding,
and nothing in adamance would notice or say so.

| Vector | Control | Status |
| --- | --- | --- |
| Profile issued to the wrong person | Profiles are issued through the same authenticated console as everything else. | **PARTIAL** |
| A profile outlives the person | Not modelled separately from account lifecycle. | **NOT MODELLED** |
| The perimeter the threat model assumes is not actually there | Nothing checks. No posture check asks whether the console is reachable from outside. | **NOT MODELLED** |

## What we do not defend against

- A device we do not manage, behaving badly on a network we do not run. These modules authenticate
  and answer. They do not police.
- An operator who turns a module on and assumes it does more than it does. That is what the build
  status banner at the top of this document is for, and it is why the DNS section says the resolver
  does not exist rather than describing what it would do.

## Still open

| ID | Item | Why it is still open |
| --- | --- | --- |
| TMN-01 | No resolver exists | G02 and G18. A filtering policy can be saved and filters nothing. |
| TMN-02 | Encrypted DNS bypass is undescribed | Decides whether the feature is meaningful at all once it exists. |
| TMN-03 | RADIUS shared-secret lifecycle | Storage on the device, rotation, and revocation are all undescribed. |
| TMN-04 | RADIUS transport posture | Nothing states whether RadSec or a tunnel is required. |
| TMN-05 | The VPN perimeter is an unverified assumption | Several main-threat-model rows depend on it and nothing checks it holds. |

## Where this came from

[`docs/DESIGN_dns.md`](DESIGN_dns.md), [`docs/DESIGN_radius_deployment.md`](DESIGN_radius_deployment.md),
[`docs/DESIGN_vpn_client_profiles.md`](DESIGN_vpn_client_profiles.md). Code:
`src/api-gateway/internal/radiussecrets/radiussecrets.go`, `src/modules/dns/blocklist/catalogue.go`,
`src/api-gateway/internal/handlers/dns/handler.go`.
