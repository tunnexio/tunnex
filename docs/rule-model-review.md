# Every feature, as an access-control subject — and the rule form that follows from it

Asked for a re-review of the whole product (site-to-site, Kubernetes, AI agents, devices, people, groups)
**before** designing the rule form, rather than patching the form one screenshot at a time. Measured from
`compiler.go` and the schema.

---

## 1. WHAT EACH FEATURE IS, WHEN IT APPEARS IN A RULE

### Can be a SOURCE — five kinds, and they are not five of the same thing

| kind | what it resolves to | granularity |
| --- | --- | --- |
| **Person** | every device owned by that user | one human's machines |
| **Group** | every device of every member (may be IdP-synced) | many humans' machines |
| **AI agent** | ⭐ **exactly one device** — the grant names `src_device_id` | one machine |
| **Site** | the LAN behind a gateway (its approved subnet CIDRs) | a whole network |
| **CIDR** | a literal prefix — a site source narrowed to one host or subnet | one host, or a slice |

⛔ **AN AGENT IS THE ONLY DEVICE NAMEABLE ON ITS OWN.** A human's laptop cannot be a source by itself; it is
reachable only through its owner or a group. That asymmetry is deliberate — `compiler.go:401` names the agent
device directly *"never a node, which would grant every device homed there"* — and it means **"device" is not
a source kind**, though the word appears everywhere else in the product.

### Can be a DESTINATION — four kinds, and TWO OF THEM ARE UNBOUNDED

| kind | what it resolves to | **port scope** |
| --- | --- | --- |
| **Resource** | a CIDR + protocol + port range | ✅ **the declared ports only** |
| **Kubernetes Service** | the Service's *current* VIP + its ports | ✅ **the declared ports only** |
| **Group** | every device of every member, as `/32`s | ⛔ **ALL PORTS, ALL PROTOCOLS** |
| **Site** | every host on that LAN | ⛔ **ALL PORTS, ALL PROTOCOLS** |

> ## **THIS IS THE MOST IMPORTANT FACT IN THE PRODUCT'S ACCESS MODEL AND THE FORM NEVER MENTIONED IT.**
> ## `compiler.go:442` and `:458` emit `Protocol: ProtoAny` — a device and a LAN are L3 destinations, so
> ## there is no port to narrow. Choosing a group as the destination is choosing *everything*.

That is why `agent rajan → group Contractors` was creatable and looked ordinary: it grants **one machine
principal unrestricted access to every device owned by every Contractor**. Nothing was wrong with the
software. Everything was wrong with what the screen let someone believe they were doing.

### Cannot be a subject at all

- **Gateway** — a *placement target*, never a source or destination. You cannot grant "to the gateway"; you
  grant to the site behind it.
- **Routed range** — never reaches the compiler. It is device-side routing, not authorization.
- **A human's device** — reachable only via its owner or a group, as above.

---

## 2. THE ASYMMETRIES A FORM MUST TEACH

1. **Port scope is a property of the DESTINATION KIND, not a field.** There is no way to narrow a group
   destination to port 443, and no way to widen a resource beyond its declared ports. The choice of noun IS
   the choice of scope.
2. **Machines and people are different principals.** An agent is one device; a person is all of theirs; a
   group is all of everyone's.
3. **Networks are different again.** A site or CIDR source has no device behind it and no owner — it is
   traffic from a LAN, and it is placed on gateways rather than on a device's node.
4. **Site and CIDR sources only place on the SOURCE gateway** unless the destination is a site or a Service
   (`compiler.go:536`, scoped in its own comment at `:490` to *"the co-located/direct case"*). A LAN reaching
   a resource behind a *different* gateway compiles a grant the far gateway never receives.
5. **`site → itself` is impossible** and is now refused server-side (`invalid_rule_self_site`).

---

## 3. THE DESIGN THAT FOLLOWS

### ⛔ The organising idea: group the options by WHAT THEY ARE, so the scope is visible at the moment of choice

Netbird's form is two flat pickers because netbird has one kind of thing. Ours has nine. A flat list of nine
teaches nothing — but **three labelled sections per side** teach the model itself:

```
SOURCE                              DESTINATION
  People                              Services        ← port-scoped
    person  · Ana Okafor                resource · gitlab (tcp/443)
    group   · Engineering               k8s      · payments (tcp/8080)
  Machines                            Networks & devices   ⛔ all ports
    agent   · rajan                     group    · Contractors
  Networks                             site     · eu-lan
    site    · eu-lan
    cidr    · type an address
```

The section header carries the fact the tag cannot: **"Services — port-scoped"** against **"Networks &
devices — all ports"**. An operator choosing a destination now sees the consequence before the click, not in
a review three weeks later.

### And the sentence, before Create

> *AI agent **rajan** will be able to reach **every device belonging to every member of Contractors** on **ALL
> ports and protocols**.*

⚠ **A DESCRIPTION, NEVER A REFUSAL.** Every pair in §1 compiles and every one has a legitimate use — an agent
that manages a fleet genuinely needs a group destination. The form's job is that the operator cannot be
surprised by their own rule, not that the product decides for them.

One extra sentence, for the one shape that is usually a mistake:

> *This gives a machine principal unrestricted access to people's own devices. If the agent needs a service,
> name that service instead — a resource is port-scoped, a group is not.*

⛔ **Attached to that shape alone.** A caution on every rule is a caution nobody reads.

### What is NOT changing

- **No new refusals.** The only server-side refusal is `site → itself`, which is impossible rather than
  unwise. Everything in §1 stays creatable.
- **The warn-not-refuse cases stay warnings** — `OUTSIDE RANGES`, `VANISHED`, `SOURCE GROUP EMPTY`, expired
  `TEMP`. All four self-clear; none becomes a form restriction.
- **No kinds hidden.** Sectioning is not a disclosure — every option is on screen, sorted.
