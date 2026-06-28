"""
Build the function-address list from a recompiler's generated C/C++ sources.

XenonRecomp / ReXGlue emit one function per guest address as ``PPC_FUNC(sub_X)``
/ ``PPC_FUNC_IMPL(__imp__sub_X)`` / ``DEFINE_REX_FUNC(sub_X)``. Those addresses
are the .pdata-derived function boundaries — feeding them to the IDA pass gives
full coverage. (You can also produce this list any other way: a .pdata dump, a
map file, etc. — one hex address per line.)

Usage:
    python extract_funcs.py <generated_dir> -o functions.txt
"""
import argparse
import os
import re

PAT = re.compile(r"(?:PPC_FUNC(?:_IMPL)?|DEFINE_REX_FUNC)\(\s*(?:__imp__)?sub_([0-9A-Fa-f]{8})")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir", help="directory with generated recompiler sources")
    ap.add_argument("-o", "--out", default="functions.txt")
    args = ap.parse_args()

    addrs = set()
    for root, _, files in os.walk(args.dir):
        for fn in files:
            if not fn.endswith((".cpp", ".c", ".cc", ".h", ".hpp")):
                continue
            with open(os.path.join(root, fn), "r", errors="ignore") as f:
                for m in PAT.finditer(f.read()):
                    addrs.add(int(m.group(1), 16))

    with open(args.out, "w") as f:
        for a in sorted(addrs):
            f.write("%08X\n" % a)
    print("wrote %s: %d functions (0x%08X .. 0x%08X)" % (
        args.out, len(addrs), min(addrs) if addrs else 0, max(addrs) if addrs else 0))


if __name__ == "__main__":
    main()
