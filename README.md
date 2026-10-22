# vmunprotect-aarch64

A runtime unpacker for **Virbox Protector / VMProtect-protected aarch64 ELF**
binaries. It recovers the code a self-decryptor generates at startup so the
binary can be statically analyzed in IDA / Ghidra.

## Why

VMProtect-class protectors (Virbox on aarch64 Linux is the common case) compile
most of a binary's `.text` into stub veneers; the real code is generated into an
anonymous executable region at process startup by a built-in self-decryptor.
Static tools read only the stubs.

The mature ecosystem is x64/Windows-only and does not fit this target:

| Tool | Scope | Fits aarch64 ELF? |
|---|---|---|
| NoVmp | VMProtect **x64** devirtualizer (needs a pre-dumped binary) | no (x64) |
| VMPStatic | **PE** static unpacker | no (PE, not ELF) |
| VTIL-Core | translation IL | arm64 *backend* exists, but it is a library, not an unpacker |

`vmunprotect-aarch64` fills the gap with the approach that actually works on
this class of target: **run it faithfully and capture the region the loader
finalizes.**

## How it works

1. Run the packed ELF under `gdb` on a faithful aarch64 environment.
2. Break on `mprotect`. The loader populates an anonymous region, then finalizes
   it with `mprotect(region, len, PROT_READ|PROT_EXEC)`.
3. Capture the largest such region and dump it to disk.
4. If the dump embeds a reconstructed ELF (a loader that writes a full image),
   report its offset so it can be carved for analysis. Symbols typically survive
   (protected builds are usually not stripped).

## Environment matrix

| Environment | Supported | Notes |
|---|---|---|
| Native arm64 Linux (bare metal / VM) | ✅ | simplest; just run `vmunprotect.py` |
| Apple Silicon Mac (arm64) | ✅ | run a Linux VM, or `qemu-system-aarch64`+HVF via `vm/run-vm.sh` |
| x86_64 host | ✅ via `vm/run-vm.sh` | boots a full aarch64 system VM; slower |
| qemu **user-mode** (`qemu-aarch64`) | ❌ | its host process segfaults on self-modifying code — do not use |

`vm/run-vm.sh` boots `qemu-system-aarch64` (HVF on Apple Silicon, KVM on native
aarch64, TCG fallback) with a cloud image and a 9p share for the target.

## Usage

Native arm64 (or inside the guest):

```bash
gdb --version        # need gdb on the aarch64 machine that will run the target
./vmunprotect.py ./packed-binary -o out/unpacked.bin
```

On a non-arm64 host, boot the harness first:

```bash
# 1. get an aarch64 Linux image (e.g. an Ubuntu/Debian cloud img)
# 2. stage the target + its non-system shared libs into ./share
./vm/run-vm.sh --image ./ubuntu-arm64.img --share ./share --ssh-port 2222
# 3. in the guest: mount -t 9p -o trans=virtio,version=9p2000.L vmshare /mnt
#    then run vmunprotect.py against the target with LD_LIBRARY_PATH set
```

Output: `out/unpacked.bin` — the dumped runtime image. If it reports an embedded
ELF offset, carve it:

```bash
dd if=out/unpacked.bin of=recovered.elf bs=1 skip=<offset>
```

Then load `recovered.elf` in IDA/Ghidra.

## Requirements

- Python 3.8+ (driver)
- `gdb` on the machine that executes the target
- For the VM path: `qemu-system-aarch64` + aarch64 UEFI firmware
  (`edk2-aarch64-code.fd` / AAVMF), auto-detected.

## Limitations

- Recovers the *image* (decoded code + strings/data). Full per-function
  decompilation of VM-virtualized routines requires decoding the VM's bytecode
  handlers — out of scope (that is a VTIL-scale project).
- The loader must actually run: targets with aggressive anti-debug beyond
  environment checks may need the VM path or further tuning.
- The target's own runtime dependencies (shared libs it needs to reach startup)
  must be present.

## Scope / legal

This is a defensive security-research tool for analyzing software you are
authorized to analyze (your own devices, firmware you are licensed to inspect,
malware research, interoperability). It does not circumvent licensing or
redistribute anyone's code; it dumps a process image you are running, for
analysis. Know your jurisdiction and your license terms.

## License

GPLv3 — see [LICENSE](LICENSE).
