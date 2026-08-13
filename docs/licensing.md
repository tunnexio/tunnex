# Tunnex licensing — what you get, and what happens if a licence lapses

⚠ **STATUS: THIS DESCRIBES THE MODEL. THE LICENCE MECHANISM IS NOT BUILT YET** (S12.1). Today every
deployment behaves as though fully licensed. This page exists so the behaviour is known *before* it ships —
particularly [the SSO consequence](#if-your-licence-lapses-and-you-use-sso-read-this-first), which is the
one an operator must not meet for the first time on the day it happens.

---

## The two tiers

| | Community | Enterprise |
| --- | --- | --- |
| **Gateways** | 1 | per band, below |
| **Organizations** | 1 | unlimited |
| **Users · devices · AI agents** | **unlimited** | **unlimited** |

**Community is the whole product on one gateway** — WireGuard and OpenVPN, the desktop client and CLI,
full-tunnel with kill-switch, the complete Zero Trust policy engine, device posture, device approval, AI
agents, Kubernetes, local auth with MFA, Access Events, the audit log at full retention, backup/restore.

**Enterprise adds:** more gateways · more organizations · SSO (Google, Microsoft Entra) · IdP directory
sync (Microsoft Entra) · support with an SLA.

### Bands

| band | gateways | annual |
| --- | --- | --- |
| Starter | up to 5 | $1,500 |
| Growth | up to 20 | $4,500 |
| Scale | unlimited | $12,000 |

**We do not count users or devices.** A 100-person company and a 1,000-person company on the same number of
gateways pay the same. The bill is a function of how many places you run, not how many people you employ.

---

## What happens when a licence expires

**Nothing stops when your licence expires.** There is no cliff, and no moment at which your VPN goes down.

| | what changes |
| --- | --- |
| **On expiry** | Nothing. A warning appears in the console |
| **For 90 days after** | Everything keeps working. You cannot **add** a gateway or an organization |
| **After 90 days** | SSO stops. Directory sync stops **adding** members — see below |

**Three things never happen, at any point:**

- **A running VPN is never stopped.** Your tunnels stay up.
- **No user is ever blocked** by a licensing state.
- **Running gateways are never stopped.** The limit applies when you **enrol** a gateway, never to one
  already running.

So a customer on Starter with five gateways whose licence lapses **keeps all five**, along with
site-to-site, cross-site DNS and gateway failover. They simply cannot add a sixth. **A fleet that is
already built stays built.**

### Directory sync after grace: additions stop, removals do not

If you use Microsoft Entra directory sync, after the grace period **new members are no longer added from
your directory** — but **removals are still applied.** Someone removed or disabled in your directory still
loses access here.

This is deliberate. **A licence may stop granting access; it must never stop removing it.** Your deployment
keeps contacting your directory for exactly this reason, and the console will say so.

⚠ **If you see "directory sync is partially licensed", that is not an error and nothing is broken.** Do not
disconnect or re-enter the credential to "fix" it — doing so is what would stop the removals.

---

## If your licence lapses and you use SSO, read this first

⛔ **This is the one lapse consequence that creates work for every person in your organization on the same
day. Plan for it before it happens.**

**Users who have only ever signed in through SSO do not have a password.** When they were first seen, an
account was created for them with no password set — there was never a reason for one. That is normal and
correct while SSO is working.

**When SSO stops at the end of the grace period, those users cannot sign in, because they have no password
to sign in with.**

**They are not locked out permanently.** Each can use **Forgot password** to set one, and it works
regardless of whether they ever had a password before.

**But:**

> ⛔ **EVERY SSO-ONLY USER MUST COMPLETE A PASSWORD RESET, AND THEY WILL ALL NEED TO DO IT AT ONCE.**
> **Password reset is delivered by email, so this only works if your deployment's email delivery is
> working.**

For a fifty-person organization, that is fifty password resets on one day, all depending on your SMTP
configuration being correct at that moment.

**What to do about it, in order of preference:**

1. **Renew before the grace period ends.** This is the whole problem, avoided.
2. **If you are letting it lapse deliberately**, verify email delivery works *first*, then ask people to set
   a password **while SSO is still working** — they can do it any time from Forgot password, and it takes
   the event off the critical day.
3. **If it has already happened**, check email delivery before anything else. Every remedy depends on it.

⚠ **Administrators are users too.** If every administrator in your organization is SSO-only, they are in
this group as well — verify at least one administrator can sign in with a password before the grace period
ends.

---

## Community forever is a supported way to use Tunnex

**Staying on Community is not a degraded state and it is not a trial that ran out.** One gateway, unlimited
users, unlimited devices, the full policy engine, indefinitely.

The usual reason to move to Enterprise is a **second site** or wanting a **standby gateway** — not a feature
you have been locked out of.
