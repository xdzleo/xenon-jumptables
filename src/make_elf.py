"""
Wrap a raw Xenon code image in a minimal 32-bit big-endian PowerPC ELF so IDA
loads it at the right virtual address with the right processor, no prompts.

A 32-bit ELF (ELFCLASS32) is used on purpose: a 64-bit container makes IDA
sign-extend 0x82.. addresses, which breaks reading the jump tables.

Usage:
    python make_elf.py image.bin image.elf --base 0x82000000 [--entry 0x82080000]
"""
import argparse
import struct


def make_elf(data: bytes, vaddr: int, entry: int) -> bytes:
    POFF = 0x1000
    e_ident = b"\x7fELF" + bytes([1, 2, 1, 0]) + b"\x00" * 8  # ELFCLASS32, ELFDATA2MSB
    eh = e_ident
    eh += struct.pack(">H", 2)       # e_type  = ET_EXEC
    eh += struct.pack(">H", 20)      # e_machine = EM_PPC
    eh += struct.pack(">I", 1)       # e_version
    eh += struct.pack(">I", entry)   # e_entry
    eh += struct.pack(">I", 52)      # e_phoff
    eh += struct.pack(">I", 0)       # e_shoff
    eh += struct.pack(">I", 0)       # e_flags
    eh += struct.pack(">H", 52)      # e_ehsize
    eh += struct.pack(">H", 32)      # e_phentsize
    eh += struct.pack(">H", 1)       # e_phnum
    eh += struct.pack(">H", 0)       # e_shentsize
    eh += struct.pack(">H", 0)       # e_shnum
    eh += struct.pack(">H", 0)       # e_shstrndx
    ph = struct.pack(">I", 1)        # p_type = PT_LOAD
    ph += struct.pack(">I", POFF)    # p_offset
    ph += struct.pack(">I", vaddr)   # p_vaddr
    ph += struct.pack(">I", vaddr)   # p_paddr
    ph += struct.pack(">I", len(data))   # p_filesz
    ph += struct.pack(">I", len(data))   # p_memsz
    ph += struct.pack(">I", 7)       # p_flags = RWX
    ph += struct.pack(">I", 0x1000)  # p_align
    out = eh + ph
    out += b"\x00" * (POFF - len(out))
    out += data
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", help="raw code image dump")
    ap.add_argument("elf", help="output ELF path")
    ap.add_argument("--base", required=True, help="image virtual base, e.g. 0x82000000")
    ap.add_argument("--entry", default=None, help="entry point (default: base + 0x80000)")
    args = ap.parse_args()

    base = int(args.base, 0)
    if base % 0x1000 != 0:
        raise SystemExit("--base must be 0x1000-aligned (got 0x%08X)" % base)
    entry = int(args.entry, 0) if args.entry else base + 0x80000
    data = open(args.image, "rb").read()
    open(args.elf, "wb").write(make_elf(data, base, entry))
    print("wrote %s (%d bytes, base 0x%08X)" % (args.elf, len(data) + 0x1000, base))


if __name__ == "__main__":
    main()
