# How a rule may and may not be made

Asked after the Add-rule form was found offering every source type against every destination type. The
answer is measured from `apps/api/internal/enterprise/policy/compiler.go`, never from the form — **the form
should mirror what the compiler does, and today nothing does.**

---

## 0. ⛔ THE FINDING, BEFORE THE MATRIX

**The form is not loose. NOTHING CONSTRAINS A PAIR, ANYWHERE.**

`CreatePolicyRule` (`enterprise/policy/service.go:332`) validates each side **independently**: that
`src_kind=group` carries a `src_group_id`, that `dst_kind=site` carries a `dst_site_id`, and so on. Twenty
checks, all of the shape *"does this side have its own id"*.

> ## **THERE IS NO CROSS-FIELD VALIDATION AT ALL.** Not one line reads the source kind and the destination
> ## kind together, and not one line asks whether they name the same thing.

⚠ **So a form-only restriction would be a guard on one caller of three.** The web UI, the `tunnex` CLI and
the GitOps CR path all reach `CreatePolicyRule` directly. Whatever is decided below belongs **server-side,
with the form mirroring it** — a dropdown that hides a combination the API still accepts has not prevented
anything, it has only stopped one of three doors from showing it.

---

## 1. THE MATRIX — 20 pairs, each with the line that decides it

Sources split across two loops that behave differently, and that split is most of the answer.

| source | → resource | → group | → site | → k8s_service |
| --- | --- | --- | --- | --- |
| **group** | ✅ | ✅ ¹ | ✅ | ✅ |
| **user** | ✅ | ✅ ¹ | ✅ | ✅ |
| **agent** | ✅ | ✅ ¹ | ✅ | ✅ |
| **site** | ⚠ ² | ⚠ ² | ✅ | ✅ |
| **cidr** | ⚠ ² | ⚠ ² | ✅ | ✅ |

**Device sources** (`group` / `user` / `agent`) — `compiler.go:388–486`. All four destinations place with
`devGrantNodes(...)`, which entitles **both** the device's gateway and the destination's gateway (`:421`,
`:452`, `:470`). These are whole.

¹ **`→ group` is the one device-source destination that places on ONE node** (`add(d.NodeID, …)` at `:439`) —
device-to-device is correct when both devices are homed on the same gateway, which is the shape S3.7
productised.

² **Site and CIDR sources place only on the SOURCE gateway** unless the destination is a site or a k8s
service (`enforceNodes := map[uuid.UUID]bool{srcGw: true}` at `:536`, extended only at `:539` and `:568`).
The compiler says so in its own words at `:490`: *"Slice 1 places the endpoints, correct for the
co-located/direct case."* **A site LAN reaching a resource or a device group behind a DIFFERENT gateway
compiles a grant the far gateway never receives.** Documented scope, not a defect — but it is exactly the
case a form should not present as equivalent to the others.

---

## 2. ⛔ THE ONE PAIR WITH NO COHERENT READING

**`site S → site S`** (and its narrowed twin, `cidr C → the site containing C`).

The compiler produces `allow(SrcIP = S's subnet, DstCIDR = S's subnet)` on S's own gateway. **Traffic between
two hosts on the same LAN is switched locally and never enters the gateway's forward chain**, so this rule
emits nft entries that cannot match, ever.

> ## **IT RENDERS `active` AND ENFORCES NOTHING — the fifth member of the warn-kind family** (`OUTSIDE
> ## RANGES`, `VANISHED`, `SOURCE GROUP EMPTY`, expired `TEMP`), and the only one the product does not
> ## currently name.

**Recommendation: refuse it at the API.** Unlike the four existing warn-kinds, this one cannot self-clear —
there is no future state of the world in which a LAN reaching itself through its own gateway starts working.
Warn-not-refuse is the right convention for *"true today, may become false"*; this is false by construction.

### ⚠ AND `group X → group X` IS NOT THE SAME CASE, THOUGH IT LOOKS LIKE IT

The compiler skips only the device reaching **itself** (`if dstIP == d.AssignedIP { continue }`, `:435`) and
grants every other pair. That is **intra-group mesh** — a real capability someone may want deliberately.

⛔ **Do not refuse it.** But the form should not *default* to it, which today it does: both pickers open on
the first group alphabetically, so the pre-filled rule is Contractors → Contractors.

---

## 3. WHAT IS **NOT** WRONG, AND MUST NOT BE "FIXED"

Two behaviours look like defects and are ruled conventions:

- **A `cidr` source outside every approved site subnet compiles to nothing** (`:519`, `cidrPlacementSite`) and
  surfaces as `OUTSIDE RANGES`. That is **warn-not-refuse (S8.7 D1)**: the CIDR may become in-world the moment
  a range is declared, so refusing it at creation would block a legitimate order of operations.
- **A site with no bound gateway grants nothing** (`:534`). Same argument — binding a gateway later makes the
  rule live.

⚠ **Converting either into a form restriction would trade a self-clearing warning for a permanent
obstruction.**

---

## 4. RECOMMENDATION — split in two, because they are different decisions

### 4a. The guard (small, server-side, no design question)

1. **Refuse `src_kind=site` with `dst_kind=site` where the ids are equal**, and `src_kind=cidr` whose CIDR
   resolves to the destination site. New error code; the form mirrors it by omitting the option.
2. **Warn — not refuse — on `group X → group X`**, and stop defaulting both pickers to the same value.
3. **Say the co-located scope out loud** on site/cidr sources with a resource or group destination: *"this
   grant is placed on <site>'s gateway only; a destination behind another gateway will not receive it."*

### 4b. ⛔ THE NETBIRD-SHAPED FORM IS A DECIDE-ITEM, NOT A FOLD — held for the founder

Netbird's policy form is **groups → groups** with a bidirectional toggle and ports. It is simpler because
their model is smaller. Ours has **five source kinds and four destination kinds** because sites (S8.1/S8.2),
CIDRs (S8.7), Kubernetes Services (S10.3) and AI agents (S15.3) each earned their own story and each has a
live call site.

> ## **A FORM THAT LOOKS LIKE NETBIRD'S EITHER HIDES CAPABILITY THIS PRODUCT HAS, OR SILENTLY DROPS KINDS.**
> ## That is the absence question in reverse — a capability with no surface is one nobody can reach.

Three shapes, for the founder to rule between:

| | what it does | what it costs |
| --- | --- | --- |
| **A — one picker per side** | A single searchable list mixing every kind, each entry tagged (`GROUP`, `SITE`, `AGENT`…). Two controls instead of four. | Nothing hidden; the tag column has to carry the type distinction the label used to. |
| **B — netbird-plain, with an "advanced" reveal** | Groups → groups by default; sites/CIDRs/agents/services behind a disclosure. | The common case gets simple. The rest becomes second-class and less discoverable. |
| **C — keep the cascade, fix the defaults and the copy** | Two selects per side as today, but no self-default, invalid pairs absent, and the placement caveat stated. | Smallest change, and the form stays four controls deep. |

**Recommendation: A.** It is the shape that gets simpler *without* hiding anything — the reason netbird's form
is two pickers is that netbird has two kinds, and imitating the layout while keeping five kinds behind a
disclosure would make our own capabilities harder to find than they are today.

⛔ **Not built. The mid-build-fork rule applies and this is a fork.**
