#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_DIR="$SCRIPT_DIR/sel4-image"
KERNEL="$IMAGE_DIR/kernel-x86_64-pc99"
INITRD="$IMAGE_DIR/capdl-loader-image-x86_64-pc99"
ISO_OUT="$SCRIPT_DIR/sel4-gateway.iso"
VMDK_OUT="$SCRIPT_DIR/sel4-gateway.vmdk"

# Verify inputs
for f in "$KERNEL" "$INITRD"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: Missing $(basename "$f") in $IMAGE_DIR" >&2
        exit 1
    fi
done

# Check tools
for cmd in grub-mkrescue qemu-img; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd not found. Install grub-pc-bin grub-common xorriso qemu-utils" >&2
        exit 1
    fi
done

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Build GRUB boot structure
mkdir -p "$TMPDIR/boot/grub"
cp "$KERNEL" "$TMPDIR/boot/"
cp "$INITRD" "$TMPDIR/boot/"

cat > "$TMPDIR/boot/grub/grub.cfg" <<'GRUBCFG'
set timeout=3
set default=0

menuentry "seL4 HTTP Gateway" {
    multiboot /boot/kernel-x86_64-pc99
    module /boot/capdl-loader-image-x86_64-pc99
    boot
}
GRUBCFG

# Create bootable ISO
echo "Creating bootable ISO..."
grub-mkrescue -o "$ISO_OUT" "$TMPDIR" 2>/dev/null

# Convert to VMDK
echo "Converting to VMDK..."
qemu-img convert -f raw -O vmdk "$ISO_OUT" "$VMDK_OUT"

echo ""
echo "=== Output ==="
echo "ISO:  $ISO_OUT ($(du -h "$ISO_OUT" | cut -f1))"
echo "VMDK: $VMDK_OUT ($(du -h "$VMDK_OUT" | cut -f1))"
echo ""
echo "=== VMware Instructions ==="
echo "1. Create a new VM: Other > Other 64-bit"
echo "2. BIOS boot mode (not UEFI)"
echo "3. Attach sel4-gateway.iso as CD-ROM, or"
echo "   Attach sel4-gateway.vmdk as hard disk"
echo "4. Allocate >= 512 MB RAM"
echo "5. Add an Intel E1000 network adapter"
echo ""
echo "=== Serial Console (REQUIRED - seL4 outputs to serial, not VGA) ==="
echo ""
echo "The VMware Console tab will be BLANK. seL4 sends all output to COM1 (IO 0x3F8)."
echo "You must add a virtual serial port to see kernel and application output."
echo ""
echo "Method 1: ESXi Web UI"
echo "  1. Edit VM Settings > Add Other Device > Serial Port"
echo "  2. Select 'Use network' > Server mode"
echo "  3. URI: telnet://:9000"
echo "  4. Power on VM, then connect: telnet <esxi-ip> 9000"
echo ""
echo "Method 2: Edit .vmx via SSH"
echo "  1. ssh root@<esxi-ip>"
echo "  2. find /vmfs/volumes -name '*.vmx' | grep <vm-name>"
echo "  3. Power off VM, then append to .vmx:"
echo "     serial0.present = \"TRUE\""
echo "     serial0.fileType = \"network\""
echo "     serial0.fileName = \"telnet://0.0.0.0:9000\""
echo "     serial0.yieldOnMsrRead = \"TRUE\""
echo "  4. Power on, then: telnet <esxi-ip> 9000"
echo ""
echo "Method 3: Log to file via .vmx"
echo "  1. Add to .vmx:"
echo "     serial0.present = \"TRUE\""
echo "     serial0.fileType = \"file\""
echo "     serial0.fileName = \"serial-output.log\""
echo "  2. ssh root@<esxi-ip>"
echo "  3. tail -f /vmfs/volumes/<datastore>/<vm-name>/serial-output.log"
echo ""
echo "See VMWARE-DEPLOY.md for full deployment guide."
