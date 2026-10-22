#!/usr/bin/env python3
"""vmunprotect — Virbox/VMProtect aarch64 ELF runtime-image unpacker.

Static analysis of a Virbox/VMProtect-protected aarch64 ELF is blocked because
most of its code is generated into an anonymous executable region at startup by
a self-decryptor. This tool runs the target under gdb on a *faithful* aarch64
environment (native arm64 host, or an aarch64 system VM) and captures that
region the moment the loader finalizes it (the loader's closing
mprotect(..., PROT_READ|PROT_EXEC) on the populated range).

It deliberately does NOT use qemu *user-mode*: qemu-aarch64's host process
segfaults on self-modifying code. Use a native arm64 machine or a full
qemu-system-aarch64 guest (see vm/run-vm.sh for a ready harness).

Usage:
    vmunprotect.py TARGET [-o OUT.bin] [--min-len BYTES] [--gdb PATH]

TARGET is the packed aarch64 ELF. The dumped runtime image is written to OUT
(default: TARGET.unpacked.bin). If the dump embeds a reconstructed ELF (a
self-decryptor that writes a full image), its offset is reported so the image
can be carved for static analysis.

Sanitized, target-agnostic: nothing here is specific to any one binary.
"""

from __future__ import annotations
import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / "capture.gdb"

ELF_MAGIC = b"\x7fELF"


def render_template(out_path: Path, min_len: int) -> str:
    text = TEMPLATE.read_text()
    text = text.replace("@OUT@", str(out_path))
    text = text.replace("@MINLEN@", str(min_len))
    return text


def find_embedded_elf(dump: bytes) -> int:
    """Offset of an embedded reconstructed ELF image, or -1."""
    idx = dump.find(ELF_MAGIC)
    # Prefer a header that also has a plausible e_machine for aarch64 (0xB7).
    while idx != -1:
        if idx + 20 <= len(dump):
            e_machine = int.from_bytes(dump[idx + 18: idx + 20], "little")
            if e_machine == 0xB7:  # EM_AARCH64
                return idx
        idx = dump.find(ELF_MAGIC, idx + 1)
    return dump.find(ELF_MAGIC)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("target", help="packed aarch64 ELF")
    ap.add_argument("-o", "--out", help="output dump path "
                    "(default: TARGET.unpacked.bin)")
    ap.add_argument("--min-len", type=int, default=1 << 20,
                    help="minimum region size to capture (default 1 MiB)")
    ap.add_argument("--gdb", default="gdb", help="gdb binary (use gdb-multiarch "
                    "inside an x86_64-driven VM harness)")
    a = ap.parse_args()

    target = Path(a.target)
    if not target.is_file():
        print(f"vmunprotect: target not found: {target}", file=sys.stderr)
        return 2
    with target.open("rb") as f:
        head = f.read(20)
    if not head.startswith(ELF_MAGIC):
        print("vmunprotect: target is not an ELF", file=sys.stderr)
        return 2
    if int.from_bytes(head[18:20], "little") != 0xB7:
        print("vmunprotect: warning: target is not EM_AARCH64", file=sys.stderr)

    out = Path(a.out) if a.out else Path(str(target) + ".unpacked.bin")
    out.parent.mkdir(parents=True, exist_ok=True)

    script = render_template(out, a.min_len)
    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as tf:
        tf.write(script)
        tpath = tf.name
    try:
        r = subprocess.run([a.gdb, "-batch", "-x", tpath, str(target)],
                           capture_output=True, text=True)
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
    finally:
        os.unlink(tpath)

    if not out.is_file() or out.stat().st_size == 0:
        print("vmunprotect: no image captured (target may not be packed, or the "
              "environment is not faithful enough — see README)", file=sys.stderr)
        return 1

    data = out.read_bytes()
    nz = sum(1 for b in data if b)
    print(f"vmunprotect: wrote {len(data)} bytes to {out} "
          f"({nz / len(data):.0%} nonzero)")
    off = find_embedded_elf(data)
    if off >= 0:
        print(f"vmunprotect: embedded reconstructed ELF at offset 0x{off:x} "
              f"(carve with: dd if={out} of=<img.elf> bs=1 skip={off})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
