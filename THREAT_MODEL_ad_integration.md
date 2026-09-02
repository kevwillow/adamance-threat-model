# Threat Model: Active Directory integration

> Status: **DRAFT, first pass, written 2026-09-01** against `b276339c`. Owner: project maintainer.
> Companion to [`docs/THREAT_MODEL.md`](THREAT_MODEL.md), which has no Active Directory boundary in
> it. This is about keeping the directory you already run, not about
> [`docs/THREAT_MODEL_samba_ad_dc.md`](THREAT_MODEL_samba_ad_dc.md), where adamance becomes the
> domain instead.

---

## What this covers

You already have Active Directory. You do not want a second place where people exist. So adamance
federates to it read-only for authentication, resolves groups from it, and keeps ownership of the
credential lifecycle on one path so a password change has one audited answer rather than two systems
racing to be authoritative.

The security question that creates is narrow and sharp: adamance now holds a credential that talks
to somebody else's directory, and an operator gets to say where that directory is.

## The control worth reading, because the attack was measured

An `identity_source` row names two things. The credential, and the LDAP server that credential is
sent to. The obvious implementation hands the credential reference to the generic secrets store.

That is a confused deputy, and it was not theorised. `secrets.Store.Get` resolves `path#field`
against the KV mount and also `file:`, `env:` and bare filesystem paths, and the gateway's
highest-value secrets are configured as exactly those forms: the session signing key, the Keycloak
admin client secret, the Postgres password, the at-rest data encryption key.

So an operator who could create an identity source could write an `ldaps_url` pointing at a host they
own and a `bind_secret_ref` of `file:/run/secrets/session_signing_key`, and the apply step would
deliver the gateway's JWT signing key to that host as a bind password, over a legitimate
configuration route. The validator accepted that exact string, along with `postgres#password` and
`../../etc/shadow`, until the fix landed
(`src/api-gateway/internal/adsecrets/bindsecret.go`).

**The rule: `bind_secret_ref` is a name, never a path.** The package owns the name to location
mapping, the prefix is a compile-time constant, and the name is re-validated at resolution rather
than trusted from the row, because the database is not a trust boundary and a row can predate a
tightened validator.

⭐ **And the second half, which is the part I would have missed.** Naming the credential correctly is
not enough if the endpoint can move underneath it. Route immutability does not fix that either,
because delete-then-create is reachable by anyone holding the write privilege and would reuse the
same credential at a new address. So the approved host is stored **with** the credential at
enrolment, and resolution refuses when it does not match the source's current endpoint. Re-pointing a
directory now requires re-enrolling the credential against the new host, which is a deliberate act
that names the destination.

The resolver holds a read-only secrets store, and an enroller built with a nil writer refuses rather
than degrading.

## Assets

| Rank | Asset | What it costs you |
| --- | --- | --- |
| 1 | The gateway's own secrets, reachable through this route if it is wrong | Session signing key, admin client secret, database password, at-rest key |
| 2 | The AD bind credential | Read of the customer's directory, at whatever scope they granted it |
| 3 | The `identity_source` rows | Where credentials go, which is the whole attack above |
| 4 | Group membership resolved from AD | Authorization input, and it comes from a system we do not control |

## Adversaries

**A13, an operator with source-write privilege.** New here, and the reason the package exists. Not a
full admin, and does not need to be. They can create configuration, and configuration is where the
credential destination lives.

**A14, the Active Directory itself.** Also new. It is upstream of authorization decisions here, so a
compromise there is an authorization compromise here, and adamance has no way to tell.

**A4, an insider on the control plane**, as before.

## Trust boundaries

| From | To | Authentication | Status |
| --- | --- | --- | --- |
| Gateway | Customer AD over LDAPS | Bind credential, bound to the approved host at enrolment | **BUILT** |
| Operator | Identity source configuration | Policy, plus name-not-path validation at resolution | **BUILT** |
| **Customer AD** | **adamance authorization** | **none. Groups arrive as an input** | **NOT MODELLED** |
| Keycloak | AD, federated read-only | Broker configuration | **PARTIAL** |

⚠️ The third row is the one to sit with. Group membership from AD feeds authorization, and nothing
here treats that directory as an adversary. If someone can add themselves to a group over there, they
have granted themselves something over here.

## Vectors and controls

| Vector | Control | Status |
| --- | --- | --- |
| Operator points a source at a host they own and exfiltrates a gateway secret | Name never path, re-validated at resolution. | **BUILT** |
| Operator re-points an existing source to move a credential | The approved host is stored with the credential, so resolution refuses on mismatch. | **BUILT** |
| Delete then re-create the source to dodge that | Anticipated. Re-enrolment is required and it names the destination. | **BUILT** |
| A path that predates the validator sits in the database | Re-validated at read, not trusted from the row. | **BUILT** |
| The federated broker is given write access to the customer directory | Read-only federation is a decision rather than a default nobody touched, and adamance owns the credential lifecycle so a password change takes one audited path. | **PARTIAL** |
| A group grants privilege here because AD said so | Nothing. See the trust-boundary note. No constraint on which AD groups may map to privileged roles, and no confirmation that group resolution is fresh. | **NOT MODELLED** |
| A disabled or deleted AD account keeps working here | Nothing. Revocation lag between the two directories is undescribed. | **NOT MODELLED** |
| LDAPS transport is downgraded or the AD certificate is not pinned | Partly covered by the main threat model's IPA CA pinning pattern, but nothing states the equivalent requirement for a customer directory. | **NOT MODELLED** |
| AD is unavailable and authentication has to decide what to do | Nothing written. Fail-closed is the product's stated posture and this path has no documented behaviour. | **NOT MODELLED** |
| A trust relationship in the customer forest brings in principals nobody expected | Nothing. Foreign principals arriving through an existing AD trust are outside anything described here. | **NOT MODELLED** |

## What we do not defend against

- A compromised Active Directory. It is upstream of us, we federate to it read-only, and if it lies
  about who someone is then we will believe it. The mitigation is that we do not write to it and we
  keep our own record of what happened here.
- The customer's own AD hygiene. Group sprawl, stale accounts and over-broad delegation are theirs.
- Anything in the forest beyond the directory we were pointed at.

## Still open

| ID | Item | Why it is still open |
| --- | --- | --- |
| TMAD-01 | AD group membership is unconstrained authorization input | No rule limits which AD groups may map to privileged roles here. |
| TMAD-02 | Revocation lag is undescribed | Disabling an account there has no stated maximum time to take effect here. |
| TMAD-03 | No stated behaviour when AD is unreachable | The product's posture is fail-closed and this path does not say. |
| TMAD-04 | Customer directory certificate trust is unstated | Nothing says what pins the LDAPS endpoint. |
| TMAD-05 | Existing forest trusts are out of scope by omission | Nobody decided that, it just was not written down. |

## Where this came from

[`docs/DESIGN_ad_setup_wizard.md`](DESIGN_ad_setup_wizard.md) §7 for the re-enrolment requirement,
[`docs/FOREST_AND_TRUST.md`](FOREST_AND_TRUST.md),
[`docs/PLAN_ad_module_slice1.md`](PLAN_ad_module_slice1.md). Code:
`src/api-gateway/internal/adsecrets/bindsecret.go`,
`src/api-gateway/internal/handlers/ad/identitysource.go`,
`src/api-gateway/internal/handlers/ad/apply.go`.
