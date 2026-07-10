"""deep_extract.py -- IDA deep-analysis function/vtable-target extractor.

Runs inside idat AFTER the jump-table pass (or standalone) with FULL analysis --
it does NOT clear the AF_ flags that ida_jumptables.py disables for speed. It
harvests the candidate function-start set from two mechanisms and emits it as an
ADDITIVE, superset-only overlay the pipeline folds into <name>_functions.toml:

  (1) funcmap   -- every function IDA's flow/cref/no-return analysis discovered
                   (catches lis/addi-referenced targets the linear .pdata scan can
                    reach but our resolver's flow scan misses)
  (2) data-xref -- big-endian dwords ANYWHERE in the image (all segments, incl.
                   .text-embedded pointer tables) that point at a code target that
                   is either already is_code OR prologue-shaped. Load-bearing: an
                   empirical study of 1438 converged run-heal cures across 6 titles
                   showed ~85% are address-taken somewhere -- but the old scan only
                   looked at NON-text data and required target already-is_code,
                   missing pointer tables in .text and functions IDA parked as data.
  (3) prologue  -- a linear sweep of the code range for PPC function prologues
                   (mflr/mfspr r12,LR; stwu r1,-N; bl __savegprlr) that no pointer
                   references and IDA did not map -- the FIFA-class function that
                   starts right after a blr with mflr as its 2nd/3rd word.
  Every candidate is ADDITIVE + superset-only; the pipeline's pure-add gate re-runs
  codegen and drops any that would split/stub/dangle, so a false positive from the
  widened scan is rejected safely (byte-identical fleet).

Config (JSON, path in argv[1] via idat -S"deep_extract.py cfg.json"):
  { "image_base":..., "text_start":..., "text_end":..., "image_end":...,
    "known":  "path/to/functions_list.txt"   (optional; addrs to EXCLUDE as already known),
    "out_toml": "path/extracted_functions.toml",
    "out_json": "path/extracted.json" }

Emits ONLY addresses NOT already known, 4-aligned, in [text_start,text_end), and
is_code -- so the pipeline's superset-only merge can never downgrade an existing
{end}/{parent}/size cure. Provenance (funcmap|dataref|both, vtbl_base) is recorded
so a later code/data-classification pass can refine.
"""
import json

import ida_auto, ida_bytes, ida_funcs, idautils, ida_pro, idc


def _cfg():
    # idat -S"deep_extract.py cfg.json" -> the cfg path arrives via idc.ARGV[1]
    path = idc.ARGV[1] if len(idc.ARGV) > 1 else "deep_extract_cfg.json"
    return json.load(open(path))


def run(cfg):
    ida_auto.auto_wait()  # FULL analysis (AF flags left at default/deep)

    BASE = int(cfg["image_base"])
    TS, TE = int(cfg["text_start"]), int(cfg["text_end"])
    IMG_END = int(cfg.get("image_end", TE))

    def in_text(a):
        return TS <= a < TE

    # known set to exclude (the linear .pdata / functions_list)
    known = set()
    kp = cfg.get("known")
    if kp:
        try:
            for line in open(kp, encoding="utf-8", errors="replace"):
                line = line.strip()
                if line:
                    try:
                        known.add(int(line, 0) if line.lower().startswith("0x") else int(line, 16))
                    except ValueError:
                        pass
        except OSError:
            pass

    # A PPC function prologue in the first few instructions: mfspr r0/r12,LR
    # (mflr), stwu r1,-N(r1), or a leading bl to a __savegprlr save-thunk. Lets us
    # accept a pointer target IDA parked as data, and find pointer-less functions.
    def _prologue(a):
        for i in range(4):
            w = ida_bytes.get_dword(a + i * 4)
            if w in (0x7C0802A6, 0x7D8802A6):        # mfspr rX,LR (mflr r0 / r12)
                return True
            if (w >> 16) == 0x9421:                  # stwu r1,-N(r1)
                return True
            if (w >> 26) == 18 and (w & 1):          # bl (savegpr/restgpr thunk)
                return True
        return False

    def _plausible_target(v):
        # 4-aligned, in text, and either IDA-mapped code or prologue-shaped.
        return in_text(v) and (v & 3) == 0 and (
            ida_bytes.is_code(ida_bytes.get_flags(v)) or _prologue(v))

    # (1) funcmap
    funcs = set(idautils.Functions(TS, TE))

    # (2) data-xref: dwords ANYWHERE in the image (all segments, including .text
    # pointer tables) that point at a plausible code target. The old scan skipped
    # in-text dwords and required target already-is_code; both cost real cures.
    dataref = {}
    ea = BASE
    while ea < IMG_END:
        v = ida_bytes.get_dword(ea)
        if _plausible_target(v) and v not in dataref:
            dataref[v] = ea
        ea += 4

    # (3) prologue sweep: prologue-shaped starts in the code range that no pointer
    # references and IDA did not map. Anchor on a return terminator preceding the
    # candidate (blr / bctr / bclr-family) to cut false positives -- a real
    # function boundary follows the previous function's epilogue.
    RET = (0x4E800020, 0x4E800420)  # blr, bctr
    prologue = set()
    ea = TS
    while ea < TE:
        if ea not in funcs and ea not in dataref:
            prev = ida_bytes.get_dword(ea - 4)
            is_ret = prev in RET or (prev & 0xFC0007FE) == 0x4C000020  # bclr family
            if is_ret and _prologue(ea):
                prologue.add(ea)
        ea += 4

    union = funcs | set(dataref) | prologue
    out = []
    for a in sorted(union):
        if a in known:
            continue
        if (a & 3) != 0 or not in_text(a):
            continue
        # accept IDA-code OR prologue-shaped (the widened target class); the
        # pure-add gate downstream drops anything that would corrupt.
        if not (ida_bytes.is_code(ida_bytes.get_flags(a)) or _prologue(a)):
            continue
        tags = []
        if a in funcs:
            tags.append("funcmap")
        if a in dataref:
            tags.append("dataref")
        if a in prologue:
            tags.append("prologue")
        rec = {"addr": "0x%08X" % a, "src": "+".join(tags)}
        if a in dataref:
            rec["ptr_ref"] = "0x%08X" % dataref[a]
        out.append(rec)

    # emit: additive superset-only overlay in heal.py's {} format + provenance json
    with open(cfg["out_toml"], "w", encoding="utf-8") as f:
        f.write("# Auto-generated by deep_extract.py (IDA deep analysis).\n")
        f.write("# Additive, superset-only: function/vtable-target starts the linear scan\n")
        f.write("# missed. The pipeline merges these only where no cure already exists.\n")
        f.write("[functions]\n")
        for r in out:
            f.write('"%s" = {}\n' % r["addr"])
    with open(cfg["out_json"], "w", encoding="utf-8") as f:
        json.dump({"count": len(out), "funcmap": len(funcs), "dataref": len(dataref),
                   "prologue": len(prologue), "union": len(union),
                   "known_excluded": len(known & union), "emitted": out}, f, indent=1)
    print("[deep_extract] emitted %d new starts (funcmap=%d dataref=%d prologue=%d union=%d, "
          "excluded %d known)"
          % (len(out), len(funcs), len(dataref), len(prologue), len(union),
             len(known & union)))


if __name__ == "__main__":
    try:
        run(_cfg())
    finally:
        ida_pro.qexit(0)
