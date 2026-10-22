#!/usr/bin/env bash
# run-vm.sh — boot a faithful aarch64 system VM for VMProtect/Virbox unpacking
# on hosts that are not natively arm64 (or where you want isolation).
#
# qemu *user-mode* cannot carry a self-modifying target (its host process
# segfaults). A full system VM is faithful enough: the Virbox loader's
# self-decryptor runs correctly under qemu-system-aarch64.
#
# Usage:
#   run-vm.sh --image IMG.qcow2 --share DIR [--ssh-port 2222] [--mem 2048]
#
#   --image  an aarch64 Linux disk image (e.g. an Ubuntu/Debian cloud img)
#   --share  host directory exported to the guest via 9p as mount_tag "vmshare"
#            (put the packed ELF + its extra shared libs there; mount in-guest
#            with: mount -t 9p -o trans=virtio,version=9p2000.L vmshare /mnt)
#
# The guest console is on unix socket ./console.sock; SSH is forwarded to
# localhost:--ssh-port. Requires qemu-system-aarch64 and an aarch64 UEFI
# firmware (edk2-aarch64-code.fd, auto-detected under common install paths).

set -euo pipefail

IMAGE=""; SHARE=""; SSHPORT=2222; MEM=2048; SMP=2
while [ $# -gt 0 ]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2;;
    --share) SHARE="$2"; shift 2;;
    --ssh-port) SSHPORT="$2"; shift 2;;
    --mem) MEM="$2"; shift 2;;
    --smp) SMP="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$IMAGE" ] && [ -n "$SHARE" ] || { echo "need --image and --share" >&2; exit 2; }
[ -f "$IMAGE" ] || { echo "image not found: $IMAGE" >&2; exit 2; }
[ -d "$SHARE" ] || { echo "share dir not found: $SHARE" >&2; exit 2; }

# Locate the aarch64 UEFI firmware.
FW=""
for c in \
  /opt/homebrew/Cellar/qemu/*/share/qemu/edk2-aarch64-code.fd \
  /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
  /usr/share/qemu/edk2-aarch64-code.fd \
  /usr/share/AAVMF/AAVMF_CODE.fd \
  /usr/share/qemu-efi-aarch64/QEMU_EFI.fd; do
  for f in $c; do [ -f "$f" ] && FW="$f" && break 2; done
done
[ -n "$FW" ] || { echo "no edk2-aarch64 firmware found; install qemu/AAVMF" >&2; exit 2; }

# HVF on Apple Silicon, KVM on Linux, else TCG (slow but works).
ACCEL="tcg"; CPU="cortex-a57"
if [ "$(uname -s)" = "Darwin" ] && [ "$(uname -m)" = "arm64" ]; then
  ACCEL="hvf"; CPU="host"
elif [ -w /dev/kvm ] && [ "$(uname -m)" = "aarch64" ]; then
  ACCEL="kvm"; CPU="host"
fi

echo "vmunprotect: accel=$ACCEL cpu=$CPU mem=$MEM image=$IMAGE share=$SHARE"
exec qemu-system-aarch64 \
  -machine virt,accel="$ACCEL" -cpu "$CPU" -m "$MEM" -smp "$SMP" \
  -bios "$FW" \
  -drive if=virtio,file="$IMAGE",format=qcow2 \
  -virtfs local,path="$SHARE",mount_tag=vmshare,security_model=none \
  -netdev user,id=net0,hostfwd=tcp::"$SSHPORT"-:22 \
  -device virtio-net-pci,netdev=net0 \
  -display none \
  -serial unix:./console.sock,server,nowait \
  -monitor unix:./monitor.sock,server,nowait
