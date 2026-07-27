# VMware ESXi Deployment Guide - seL4 HTTP Gateway

## VM Creation

1. **New VM**: Guest OS = "Other" > "Other 64-bit"
2. **Boot mode**: BIOS (not UEFI) - GRUB multiboot requires legacy BIOS
3. **RAM**: 512 MB minimum
4. **Disk**: Attach `sel4-gateway.vmdk` as hard disk, or `sel4-gateway.iso` as CD-ROM
5. **NIC**: Intel E1000 (required - seL4 driver expects E1000)

## Serial Console Setup (Required)

**The VMware Console tab will be blank.** seL4 outputs all kernel and application messages to COM1 serial (IO 0x3F8). You must configure a virtual serial port to see any output.

### Method 1: ESXi Web UI (Recommended)

1. Edit VM Settings > **Add Other Device** > **Serial Port**
2. Select **Use network** > **Server mode**
3. Set URI: `telnet://:9000`
4. Start the VM
5. Connect from your workstation:
   ```
   telnet <esxi-ip> 9000
   ```

### Method 2: Edit .vmx via SSH

1. SSH into ESXi:
   ```
   ssh root@<esxi-ip>
   ```
2. Locate the VM config:
   ```
   find /vmfs/volumes -name "*.vmx" | grep <vm-name>
   ```
3. **Power off the VM**, then append these lines to the `.vmx` file:
   ```
   serial0.present = "TRUE"
   serial0.fileType = "network"
   serial0.fileName = "telnet://0.0.0.0:9000"
   serial0.yieldOnMsrRead = "TRUE"
   ```
4. Power on the VM, then connect:
   ```
   telnet <esxi-ip> 9000
   ```

### Method 3: Log to File

Useful when you don't need interactive access, just want to capture output.

1. **Power off the VM**, then add to `.vmx`:
   ```
   serial0.present = "TRUE"
   serial0.fileType = "file"
   serial0.fileName = "serial-output.log"
   ```
2. Power on the VM, then tail the log:
   ```
   ssh root@<esxi-ip>
   tail -f /vmfs/volumes/<datastore>/<vm-name>/serial-output.log
   ```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Blank VMware Console tab | seL4 outputs to serial, not VGA | Configure serial port (see above) |
| No serial output | VM not booting | Check BIOS boot mode, verify ISO/VMDK attached |
| Telnet connection refused | Serial port not configured or wrong port | Verify `.vmx` settings, check firewall on ESXi |
| No network after boot | Wrong NIC type | Ensure NIC is Intel E1000, not VMXNET3 |
| GRUB menu but no seL4 | Missing kernel/initrd in ISO | Rebuild with `make-vmware-image.sh` |
