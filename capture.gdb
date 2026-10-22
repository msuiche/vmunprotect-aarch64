# capture.gdb — Virbox/VMProtect aarch64 ELF runtime-image capture (template).
#
# Generic and target-agnostic. The Virbox/VMProtect self-decryptor populates an
# anonymous executable region at startup and finalizes it with
# mprotect(region, len, PROT_READ|PROT_EXEC). This script breaks on mprotect,
# captures the largest such region (the runtime image), and dumps it to @OUT@.
#
# @OUT@ and @MINLEN@ are substituted by the driver (vmunprotect.py).
#
# Works under native aarch64 gdb, or gdb inside a qemu-system-aarch64 guest.
# qemu user-mode is NOT viable (its host process crashes on self-modifying
# code) — use a system VM or a native arm64 host.

set pagination off
set confirm off
set breakpoint pending on

set $rgn_base = 0
set $rgn_len = 0
set $minlen = @MINLEN@

# mprotect(addr=$x0, len=$x1, prot=$x2). PROT_EXEC=4, PROT_WRITE=2, PROT_READ=1.
# The loader writes with W|X (6/7) then finalizes R-X (5). Capture the largest
# region that ends up readable+executable.
break mprotect
commands
    silent
    if $x1 >= $minlen && ($x2 & 1) && ($x2 & 4)
        if $x1 > $rgn_len
            set $rgn_base = $x0
            set $rgn_len = $x1
        end
    end
    continue
end

# Dump at normal exit (region is finalized by then if it ever was).
break _exit
commands
    silent
    if $rgn_base != 0
        dump memory @OUT@ $rgn_base ($rgn_base + $rgn_len)
        printf "vmunprotect: dumped %ld bytes from %p\n", $rgn_len, $rgn_base
    end
    continue
end

run

# Fallback: dump at termination/crash even if _exit was not reached cleanly.
if $rgn_base != 0
    dump memory @OUT@ $rgn_base ($rgn_base + $rgn_len)
    printf "vmunprotect: dumped %ld bytes from %p (final)\n", $rgn_len, $rgn_base
else
    printf "vmunprotect: no populated region captured\n"
end
quit
