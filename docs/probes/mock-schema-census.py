#!/usr/bin/env python3
"""Census every object literal in apps/web/test against the OpenAPI schema it claims to represent.

BOTH DIRECTIONS, because they fail differently and BOTH PASS:
  INVENTED  a key the mock has and the schema does not -> the test exercises a field production never sends
  OMITTED   a REQUIRED key the schema has and the mock does not -> the test never sees a field always present

The empty `name` (fixture) and the phantom `active` (mock) were one of each.
"""
import io, os, re, sys, glob, collections

ROOT = "/Users/pawangupta/tunnex"
SPEC = os.path.join(ROOT, "openapi", "openapi.yaml")

# ── parse components.schemas: name -> (required set, property set) ────────────────────────────────────────
schemas = {}
lines = io.open(SPEC).read().split("\n")
i = 0
while i < len(lines) and lines[i].strip() != "schemas:":
    i += 1
i += 1
cur = None
while i < len(lines):
    l = lines[i]
    if l and not l.startswith(" "):
        break
    m = re.match(r"^    (\w+):\s*$", l)
    if m:
        cur = m.group(1)
        schemas[cur] = {"required": set(), "props": set()}
    elif cur:
        rm = re.match(r"^      required:\s*\[(.*)\]", l)
        if rm:
            schemas[cur]["required"] = {x.strip() for x in rm.group(1).split(",") if x.strip()}
        if re.match(r"^      properties:\s*$", l):
            j = i + 1
            while j < len(lines) and (lines[j].startswith("        ") or not lines[j].strip()):
                pm = re.match(r"^        (\w+):", lines[j])
                if pm:
                    schemas[cur]["props"].add(pm.group(1))
                j += 1
    i += 1

# ── pull top-level object literals out of the test files ─────────────────────────────────────────────────
def literals(src):
    out = []
    for start in (m.start() for m in re.finditer(r"\{", src)):
        depth, j = 0, start
        while j < len(src):
            if src[j] == "{": depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0: break
            j += 1
        if j >= len(src) or j - start > 900:
            continue
        body = src[start:j + 1]
        # ⛔ DEPTH-1 KEYS ONLY. Collecting every `key:` in the body pulls in NESTED literals, so an outer mock
        # wrapper inherits its rows' keys and matches a schema it is not. That produced a census of false
        # positives on the first run — and a noisy census is not a census.
        keys, d, k = set(), 0, 0
        while k < len(body):
            c = body[k]
            if c in "{[(":
                d += 1
            elif c in "}])":
                d -= 1
            elif d == 1:
                m2 = re.match(r"([A-Za-z_]\w*)\s*:", body[k:])
                if m2 and (k == 0 or body[k-1] in "{,\n \t"):
                    keys.add(m2.group(1))
                    k += m2.end() - 1
            k += 1
        if len(keys) >= 3:
            out.append((start, keys, body))
    return out

def line_of(src, pos):
    return src.count("\n", 0, pos) + 1

findings, unmatched = [], []
files = sorted(glob.glob(os.path.join(ROOT, "apps/web/test/*.ts")) +
               glob.glob(os.path.join(ROOT, "apps/web/test/*.tsx")))
for f in files:
    src = io.open(f).read()
    # ⛔ STRIP COMMENTS FIRST. Prose inside a comment contains "word:" and the depth-1 key scanner cannot tell
    # that from a property — it reported `here` as an invented Device field, from the sentence "...stays FALSE
    # here: only ONE seeded device...". Blank the comment bodies but KEEP the newlines so line numbers hold.
    src = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), src, flags=re.S)
    src = re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), src)
    seen = set()
    for pos, keys, body in literals(src):
        if keys & {"GET","POST","PUT","PATCH","DELETE","data","error"}:
            continue
        # ⛔ camelCase => a VIEW-MODEL input type, not the wire DTO. Those are allowed their own shape, and
        # matching them against a spec schema manufactures findings. Wire DTOs are snake_case throughout.
        if any(re.search(r"[a-z][A-Z]", k) for k in keys):
            continue
        best, score = None, 0
        for name, s in schemas.items():
            if not s["props"]:
                continue
            ov = len(keys & s["props"])
            # Require a real overlap AND that the schema's required set is mostly present — otherwise a
            # 3-key literal matches half the spec.
            if ov > score and ov >= 3 and len(keys & s["required"]) >= max(2, len(s["required"]) // 2):
                best, score = name, ov
        if not best:
            continue
        sig = (best, tuple(sorted(keys)))
        if sig in seen:
            continue
        seen.add(sig)
        s = schemas[best]
        invented = keys - s["props"]
        omitted = s["required"] - keys
        if invented or omitted:
            findings.append((os.path.relpath(f, ROOT), line_of(src, pos), best,
                             sorted(invented), sorted(omitted)))

# ⛔ THE TWO DIRECTIONS ARE NOT EQUALLY SEVERE, and reporting them as one list would bury the real ones.
#   INVENTED  is ALWAYS a defect: the test exercises a field production never sends.
#   OMITTED   is usually FINE — a mock carries the fields its test asserts on. It becomes a defect only when
#             THE CODE UNDER TEST READS THAT FIELD, which is what happened with `status` and `name`.
def target_src(testfile):
    """Xwiring.test.tsx -> src/pages/X.tsx ; Xview.test.ts -> src/lib/Xview.ts. A GLOBAL grep over all of
    src answers 'does anything read this', which is not the question — the question is whether THE PAGE
    UNDER TEST reads it."""
    b = os.path.basename(testfile).split(".")[0]
    cands = []
    if b.endswith("wiring"):
        stem = b[:-6]
        cands += glob.glob(os.path.join(ROOT, "apps/web/src/pages/*.tsx"))
        cands = [c for c in cands if os.path.basename(c).lower().startswith(stem)]
        cands += [c for c in glob.glob(os.path.join(ROOT, "apps/web/src/lib/*.ts"))
                  if os.path.basename(c).lower().startswith(stem)]
    else:
        cands += [c for c in glob.glob(os.path.join(ROOT, "apps/web/src/lib/*.ts"))
                  if os.path.basename(c).lower().startswith(b.replace("view", ""))]
    return "".join(io.open(c).read() for c in cands), [os.path.basename(c) for c in cands]

print("SCHEMAS PARSED: %d   TEST FILES SCANNED: %d\n" % (len(schemas), len(files)))
if not findings:
    print("no mismatches")
else:
    print("=" * 100)
    print("DIRECTION 1 — INVENTED: a field the mock has and the schema does NOT. Always a defect.")
    print("=" * 100)
    n_inv = 0
    for f, ln, sc, inv, om in findings:
        for k in inv:
            print("  %-38s:%-5d %-14s `%s`" % (f, ln, sc, k)); n_inv += 1
    if not n_inv: print("  NONE")

    print()
    print("=" * 100)
    print("DIRECTION 2 — OMITTED *AND READ BY THE CODE*: the mock never shows the page a field it reads.")
    print("=" * 100)
    n_om = 0
    benign = 0
    for f, ln, sc, inv, om in findings:
        for k in om:
            tsrc, tnames = target_src(os.path.join(ROOT, f))
            if tsrc and re.search(r"\.%s\b" % re.escape(k), tsrc):
                print("  %-38s:%-5d %-14s `%s`  <- read by %s" % (f, ln, sc, k, ",".join(tnames))); n_om += 1
            else:
                benign += 1
    if not n_om: print("  NONE")
    print()
    print("  omitted-but-never-read (benign partial fixtures, not reported): %d" % benign)
print("\ntotal literals with a mismatch: %d   INVENTED: %d   OMITTED-AND-READ: %d" % (len(findings), n_inv, n_om))
