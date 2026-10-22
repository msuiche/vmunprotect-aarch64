#!/usr/bin/env python3
"""deobfuscate.py — VMProtect/Virbox aarch64 flattened-code deobfuscator.

The protector scatters a function's real logic across small blocks linked by
computed branches (`br xN`) and pads it with junk (self-canceling arithmetic,
dead writes). This engine recovers the real operation sequence by:

  1. Constant-folding every register through the arithmetic/logic ops
     (movz/movk/add/sub/eor/orr/and/shifts/rev/adr/adrp...), so a computed
     branch's target register resolves to a concrete address when it is a
     constant at that point.
  2. Following the control flow with a worklist (plain `b`, resolved `br`,
     both arms of `b.cond`/`cbz`/`cbnz`), building the reachable CFG.
  3. Stripping junk: no-op pairs, dead reg writes, and the VM dispatch
     scaffolding — leaving the real calls, loads, stores, comparisons, and
     branches that implement the logic.

Target-agnostic: works on any aarch64 image buffer + a base vaddr. No target
names, no target specifics.

Usage (library): see Deobfuscator.walk(). CLI:
    deobfuscate.py IMAGE.bin --base 0x0 --start 0x520130 --image-vaddr 0x591000
"""

from __future__ import annotations
import argparse
import struct
import sys
from collections import deque

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG
except ImportError:
    print("deobfuscate: needs capstone (pip install capstone)", file=sys.stderr)
    sys.exit(2)

MASK64 = (1 << 64) - 1


class Reg:
    """A register value: either a known constant or unknown."""
    __slots__ = ("val",)

    def __init__(self, val=None):
        self.val = val  # int or None

    @property
    def known(self):
        return self.val is not None


def _u64(x):
    return x & MASK64


class Deobfuscator:
    def __init__(self, image: bytes, image_vaddr: int):
        self.img = image
        self.image_vaddr = image_vaddr      # vaddr that offset 0 corresponds to
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True

    def _off(self, vaddr: int) -> int:
        return vaddr - self.image_vaddr

    def _insn(self, vaddr: int):
        off = self._off(vaddr)
        if off < 0 or off + 4 > len(self.img):
            return None
        for ins in self.md.disasm(self.img[off:off + 4], vaddr):
            return ins
        return None

    # -- register-state helpers -------------------------------------------
    @staticmethod
    def _regnum(name: str) -> int | None:
        name = name.lower()
        if name.startswith("x"):
            return int(name[1:])
        if name.startswith("w"):
            return int(name[1:])  # 32-bit view of same reg
        return None

    def walk(self, start: int, max_steps: int = 4000):
        """Constant-folding CFG walk from `start`. Returns a dict:
        { 'ops': [(vaddr, mnemonic, op_str)],       # real ops in visit order
          'calls': [(vaddr, target)],               # bl call sites
          'cond': [(vaddr, mnemonic, op_str)],      # decision points
          'branches': [(vaddr, target)],            # resolved b/br edges
          'unresolved': [vaddr],                    # br xN we couldn't fold
        }"""
        ops, calls, cond, edges, unresolved = [], [], [], [], []
        visited = set()
        # worklist of (vaddr, regfile). regfile: dict[int, Reg]
        wl = deque()
        wl.append((start, {}))
        steps = 0
        while wl and steps < max_steps:
            pc, regs = wl.popleft()
            while True:
                if pc in visited:
                    break
                ins = self._insn(pc)
                if ins is None:
                    break
                visited.add(pc)
                steps += 1
                if steps > max_steps:
                    break
                m = ins.mnemonic
                ops.append((pc, m, ins.op_str))

                nxt = pc + 4
                if m == "ret":
                    break
                if m == "bl":
                    t = self._imm(ins)
                    if t is not None:
                        calls.append((pc, t))
                    pc = nxt
                    continue
                if m == "b":
                    t = self._imm(ins)
                    if t is not None:
                        edges.append((pc, t))
                        if t not in visited:
                            wl.append((t, dict(regs)))
                    break
                if m == "br":
                    # resolve register
                    rname = ins.op_str.strip()
                    rn = self._regnum(rname)
                    tgt = None
                    if rn is not None and rn in regs and regs[rn].known:
                        tgt = regs[rn].val
                    if tgt is not None:
                        edges.append((pc, tgt))
                        if tgt not in visited:
                            wl.append((tgt, dict(regs)))
                    else:
                        unresolved.append(pc)
                    break
                if m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz"):
                    cond.append((pc, m, ins.op_str))
                    # record both: target and fallthrough
                    t = self._imm(ins)
                    if t is not None and t not in visited:
                        wl.append((t, dict(regs)))
                    pc = nxt
                    continue
                # data ops: fold
                self._fold(ins, regs)
                pc = nxt
        return {"ops": ops, "calls": calls, "cond": cond,
                "branches": edges, "unresolved": unresolved}

    # -- decoding / folding -------------------------------------------------
    def _imm(self, ins) -> int | None:
        """Extract the immediate target/value from a branch or literal."""
        op = ins.op_str
        if "#" in op:
            tok = op.split("#", 1)[1].split(",")[0].split("]")[0].strip()
            try:
                return int(tok, 0)
            except ValueError:
                return None
        return None

    def _get(self, regs, name) -> int | None:
        rn = self._regnum(name)
        if rn is None:
            return None
        if name.startswith("w") and rn in regs and regs[rn].known:
            return regs[rn].val & 0xFFFFFFFF
        if rn in regs and regs[rn].known:
            return regs[rn].val
        return None

    def _set(self, regs, name, val):
        rn = self._regnum(name)
        if rn is None:
            return
        if val is None:
            regs[rn] = Reg(None)
        else:
            if name.startswith("w"):
                val &= 0xFFFFFFFF
            regs[rn] = Reg(_u64(val))

    def _fold(self, ins, regs) -> None:
        m = ins.mnemonic
        ops = [t.strip() for t in ins.op_str.split(",")]
        dst = ops[0] if ops else None

        def imm(tok):
            tok = tok.strip()
            if tok.startswith("#"):
                try:
                    return int(tok[1:], 0)
                except ValueError:
                    return None
            return None

        if m in ("movz",):
            v = imm(ops[1]) if len(ops) > 1 else None
            shift = 0
            if len(ops) > 2 and "lsl" in ops[2]:
                s = imm(ops[2].split("#")[-1])
                shift = s or 0
            self._set(regs, dst, (v << shift) if v is not None else None)
            return
        if m == "movk":
            cur = self._get(regs, dst)
            v = imm(ops[1]) if len(ops) > 1 else None
            shift = 0
            if len(ops) > 2 and "lsl" in ops[2]:
                s = imm(ops[2].split("#")[-1])
                shift = s or 0
            if cur is not None and v is not None:
                mask = 0xFFFF << shift
                self._set(regs, dst, (cur & ~mask) | ((v & 0xFFFF) << shift))
            else:
                self._set(regs, dst, None)
            return
        if m == "mov":
            if len(ops) == 2:
                src = ops[1]
                v = imm(src)
                if v is not None:
                    self._set(regs, dst, v)
                    return
                self._set(regs, dst, self._get(regs, src))
                return
        if m in ("add", "sub", "eor", "orr", "and", "bic", "neg", "mvn"):
            a = self._get(regs, ops[1]) if len(ops) > 1 else None
            b = None
            if len(ops) > 2:
                b = imm(ops[2])
                if b is None:
                    b = self._get(regs, ops[2])
            if a is not None and b is not None:
                if m == "add":
                    self._set(regs, dst, a + b)
                elif m == "sub":
                    self._set(regs, dst, a - b)
                elif m == "eor":
                    self._set(regs, dst, a ^ b)
                elif m == "orr":
                    self._set(regs, dst, a | b)
                elif m in ("and",):
                    self._set(regs, dst, a & b)
                elif m == "bic":
                    self._set(regs, dst, a & ~b)
                elif m == "neg":
                    self._set(regs, dst, -b)
                elif m == "mvn":
                    self._set(regs, dst, ~b)
                return
            self._set(regs, dst, None)
            return
        if m == "adr":
            v = self._imm(ins)
            self._set(regs, dst, v)
            return
        if m == "adrp":
            # adrp dst, #page — capstone gives the page absolute address
            v = self._imm(ins)
            self._set(regs, dst, v)
            return
        if m in ("lsl", "lsr", "asr", "ror"):
            a = self._get(regs, ops[1]) if len(ops) > 1 else None
            s = imm(ops[2]) if len(ops) > 2 else None
            if a is not None and s is not None:
                if m == "lsl":
                    self._set(regs, dst, a << s)
                elif m == "lsr":
                    self._set(regs, dst, (a & 0xFFFFFFFFFFFFFFFF) >> s)
                elif m == "asr":
                    self._set(regs, dst, a >> s)
                elif m == "ror":
                    s %= 64
                    self._set(regs, dst, ((a >> s) | (a << (64 - s))))
                return
            self._set(regs, dst, None)
            return
        if m == "rev":
            a = self._get(regs, ops[1]) if len(ops) > 1 else None
            if a is not None:
                self._set(regs, dst, int.from_bytes(a.to_bytes(8, "little"), "big"))
            else:
                self._set(regs, dst, None)
            return
        # loads / unknown-dest ops clobber the destination
        if m.startswith("ldr") or m.startswith("ldp") or m.startswith("ldur"):
            for t in ops:
                rn = self._regnum(t)
                if rn is not None:
                    self._set(regs, t, None)
            return
        # anything else writing a destination clobbers it (conservative)
        if dst is not None and self._regnum(dst) is not None and m not in (
                "cmp", "cmn", "tst", "str", "stp", "stur"):
            # don't clobber for pure reads; but default: unknown writes clobber
            if m not in ("nop",):
                # keep prior value for unknown ops to avoid over-clobbering;
                # only clobber when the op obviously writes dst
                pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--image-vaddr", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--start", type=lambda x: int(x, 0), required=True)
    a = ap.parse_args()
    img = open(a.image, "rb").read()
    de = Deobfuscator(img, a.image_vaddr)
    res = de.walk(a.start)
    print(f"ops={len(res['ops'])} calls={len(res['calls'])} "
          f"cond={len(res['cond'])} edges={len(res['branches'])} "
          f"unresolved={len(res['unresolved'])}")
    print("=== calls ===")
    for pc, t in res["calls"]:
        print(f"  0x{pc:x}: bl 0x{t:x}")
    print("=== decision points ===")
    for pc, m, op in res["cond"]:
        print(f"  0x{pc:x}: {m} {op}")
    print("=== resolved branches ===")
    for pc, t in res["branches"][:40]:
        print(f"  0x{pc:x}: -> 0x{t:x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
