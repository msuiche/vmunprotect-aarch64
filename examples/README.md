# Examples

A minimal end-to-end run on a native arm64 Linux host (or inside the guest VM).

## 1. Confirm the target is a packed aarch64 ELF

```bash
file ./packed-binary
# -> ELF 64-bit LSB pie executable, ARM aarch64, ... not stripped
```

A Virbox/VMProtect-packed aarch64 ELF shows a cluster of small `.text` sections
plus a large `.bss`, and `mprotect` among its imports:

```bash
objdump -h ./packed-binary | grep -E '\.text|\.bss'
objdump -T ./packed-binary | grep -w mprotect
```

## 2. Unpack

```bash
gdb --version            # must be present on the machine running the target
../vmunprotect.py ./packed-binary -o out/unpacked.bin
```

Expected output:

```
vmunprotect: wrote 8388608 bytes to out/unpacked.bin (38% nonzero)
vmunprotect: embedded reconstructed ELF at offset 0x0 (carve with: dd ...)
```

## 3. Carve and analyze

```bash
dd if=out/unpacked.bin of=recovered.elf bs=1 skip=0
# load recovered.elf in IDA/Ghidra — symbols usually survive (not stripped)
strings -n 6 recovered.elf | sort -u | less
```

## 4. On a non-arm64 host

Use the system-VM harness (`../vm/run-vm.sh`) to boot a faithful aarch64 guest,
share the target over 9p, install gdb in the guest, and run the driver there.
See the top-level README's environment matrix.
