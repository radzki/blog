---
layout: post
title: "Flashing Android on the MK809III: A Story of Fake Bricks"
description: "Recovering an RK3188 Android stick from a corrupted bootloader using Mask ROM mode, rkflashtool, and Rockchip's upgrade_tool"
date: 2026-03-11
tags: [embedded, android, rockchip, firmware, hardware]
---

## Introduction

I have an MK809III — a tiny Android stick from around 2013, built around a Rockchip RK3188 SoC. It's been running a custom Debian Linux setup for a while, but I wanted to get stock Android back on it.

Simple enough, right?

Three approaches later, with the device appearing completely dead, I finally got it working. Here's everything I learned — including the mistake that looked like a brick but wasn't.

**The Goal**: Flash stock Android 4.4 onto the MK809III's eMMC.

**The Device**:
- **SoC**: Rockchip RK3188 (quad-core Cortex-A9, 28nm)
- **Storage**: 8GB eMMC (accessed as MTD/NAND from the bootloader)
- **Firmware**: `T010_8723bs_4.4_1080_20140924.img` (519MB RKFW package)

---

## Part 1: The Firmware Package

Rockchip firmware comes packaged as an RKFW file, which is a nested container format. The outer wrapper is unpacked with `afptool`:

```bash
./rkflashtool/afptool -unpack T010_8723bs_4.4_1080_20140924.img partitions/
```

This gives you the actual partition images:

| File | Size | Partition |
|---|---|---|
| `misc.img` | 48K | misc (bootloader flags) |
| `kernel.img` | 11M | kernel |
| `boot.img` | 12M | boot (ramdisk) |
| `recovery.img` | 15M | recovery |
| `system.img` | 482M | system (Android OS) |
| `RK3188Loader(L)_V2.13.bin` | 197K | bootloader |
| `parameter` | 645B | partition table |

The `parameter` file is the most important one — it defines the partition layout in the eMMC:

```
CMDLINE:...mtdparts=rk29xxnand:0x00002000@0x00002000(misc),
0x00006000@0x00004000(kernel),0x00006000@0x0000a000(boot),
0x00010000@0x00010000(recovery),...0x00180000@0x005e2000(system),...
```

---

## Part 2: SD Card Upgrade Mode — Doesn't Work

Rockchip devices have an SD card upgrade mechanism: write the bootloader, signed parameter, and firmware to specific sectors of an SD card, insert it, and the device auto-flashes from it.

I wrote all three components to the card using `dd`:

```bash
# Bootloader at sector 64
sudo dd if='RK3188Loader(L)_V2.13.bin' of=/dev/sda seek=64 conv=sync,fsync bs=512

# Signed parameter at sector 0x2000
./rkflashtool/rkcrc -p partitions/parameter parameter_android.img
sudo dd if=parameter_android.img of=/dev/sda seek=$((0x2000)) conv=sync,fsync bs=512

# Firmware at sector 0x4000
sudo dd if=T010_8723bs_4.4_1080_20140924.img of=/dev/sda seek=$((0x4000)) conv=sync,fsync bs=512
```

Inserted the card, powered on. The device booted straight into the miniroot shell — completely ignoring the SD card upgrade image. The automatic upgrade mechanism never triggered.

---

## Part 3: MTD Flashing from the Miniroot — Catastrophic Success

If the automatic upgrade doesn't work, maybe I can just flash the partitions manually from the miniroot shell. The miniroot does have a shell, after all.

From inside the miniroot:

```sh
cat /proc/mtd
```

```
dev:   size   erasesize  name
mtd0: 00400000 00000000 "misc"
mtd1: 01000000 00004000 "boot"
mtd2: 01000000 00004000 "kernel"
mtd3: 02000000 00004000 "recovery"
mtd4: 1ca400000 00004000 "system"
```

The eMMC was accessible as MTD block devices. I mounted the SD card's ext4 partition, verified the images were there, and started writing:

```sh
mount /dev/mmcblk0p1 /mnt
dd if=/mnt/android/misc.img     of=/dev/mtdblock0
dd if=/mnt/android/kernel.img   of=/dev/mtdblock2
dd if=/mnt/android/boot.img     of=/dev/mtdblock1
dd if=/mnt/android/recovery.img of=/dev/mtdblock3
dd if=/mnt/android/system.img   of=/dev/mtdblock4
sync
```

Everything wrote without errors. Removed the SD card, powered off, powered on.

Nothing. No LED, no HDMI output, no response of any kind.

The device appeared completely dead.

---

## Part 4: The "Brick" That Wasn't

The first instinct with a dead board is to panic. The second is to connect it to a PC via USB and check `lsusb`.

```bash
lsusb | grep 2207
```

```
Bus 001 Device 013: ID 2207:310b Fuzhou Rockchip Electronics Company RK3188 in Mask ROM mode
```

The device was alive. It had fallen back to **Mask ROM mode** — a hardwired ROM in the RK3188 that activates when the bootloader on eMMC is invalid or absent. This is a hardware feature that literally cannot be disabled, so RK3188 devices genuinely cannot be permanently bricked through software.

What happened: `mtdblock0` ("misc") is not just the Android misc partition. The RK3188 stores its **IDB (ID Block)** bootloader at the very beginning of the NAND — which overlaps with the misc MTD partition's physical location. Writing `misc.img` to `mtdblock0` overwrote the IDB blocks, leaving the device with no valid bootloader to run.

Mask ROM mode communicates over USB using the rockusb protocol. With the right tools, we can reflash everything from the PC.

---

## Part 5: Recovering via USB

### Tools

- `rkflashtool` — open source rockusb client, handles partition flashing
- Rockchip's `upgrade_tool` — proprietary binary, needed for writing the bootloader (more on why below)

```bash
git clone https://github.com/neo-technologies/rkflashtool.git
cd rkflashtool && make && cd ..

# upgrade_tool lives in the rkbin repo
git clone --depth 1 https://github.com/rockchip-linux/rkbin.git
```

### Step 1 — Initialize the Device

In Mask ROM mode, the device has no RAM initialized and no USB loader running. Before you can talk to it properly, you need to upload two binary blobs:

1. **DDR init**: initializes the LPDDR2 RAM
2. **USB plug**: the miniloader that speaks the full rockusb protocol

Both are embedded inside `RK3188Loader(L)_V2.13.bin` in a Rockchip-specific packed format. Extract them with Python:

```python
d = open('RK3188Loader(L)_V2.13.bin', 'rb').read()
open('rk3188_ddr.bin', 'wb').write(d[0x14a:0x14a+12288])
open('rk3188_usbplug.bin', 'wb').write(d[0x314a:0x314a+59392])
```

Then upload them:

```bash
sudo ./rkflashtool/rkflashtool l < rk3188_ddr.bin    # Load DDR init
sudo ./rkflashtool/rkflashtool L < rk3188_usbplug.bin # Load USB plug

# Verify
sudo ./rkflashtool/rkflashtool v
# chip version: 310B-2013.01.31-V101
```

The device is now in rockusb mode and ready to accept flash operations.

### Step 2 — Write the Partition Table

```bash
sudo ./rkflashtool/rkflashtool P < partitions/parameter
```

### Step 3 — Write the Partition Images

`rkflashtool w` accepts a partition name and uses the parameter file to find the correct offset automatically:

```bash
sudo ./rkflashtool/rkflashtool w misc     < partitions/Image/misc.img
sudo ./rkflashtool/rkflashtool w kernel   < partitions/Image/kernel.img
sudo ./rkflashtool/rkflashtool w boot     < partitions/Image/boot.img
sudo ./rkflashtool/rkflashtool w recovery < partitions/Image/recovery.img
sudo ./rkflashtool/rkflashtool w system   < partitions/Image/system.img  # 482MB, ~5 min
```

### Step 4 — Write the Bootloader (and Why rkflashtool Can't Do It)

`rkflashtool` has a `j` command for writing "IDBlocks" (raw NAND sectors). But it sends raw 512-byte blocks — it has no idea about the IDB format the RK3188 BootROM expects.

The IDB format is non-trivial:
- Magic number at sector 0 is RC4-encrypted with a fixed key
- The header contains offsets to DDR init and miniloader stages
- Multiple redundant copies are written at sector offsets `64 + 1024*n`

Rockchip's `upgrade_tool` handles all of this internally:

```bash
sudo rkbin/tools/upgrade_tool ul 'partitions/RK3188Loader(L)_V2.13.bin'
```

```
Loading loader...
Support Type:RK310B   Loader ver:2.13   Loader Time:2014-03-03 18:08:38
Prepare IDB Start
Prepare IDB Success
Download IDB Start
Download IDB Success
Upgrade loader ok.
```

### Step 5 — Reboot

```bash
sudo ./rkflashtool/rkflashtool b
```

Android boots. First boot takes about 60 seconds while it initializes the userdata partition.

---

## What I Got Wrong

### Writing misc.img to mtdblock0

The "misc" MTD partition and the bootloader IDB blocks physically share the same area of NAND. From the miniroot's perspective, `mtdblock0` is the misc partition and writing misc.img to it should be fine. But the RK3188 BootROM reads IDB blocks starting at physical sector 64, which is within that same area. Overwriting it with Android's misc.img (a tiny 48K file mostly full of zeros) killed the IDB.

**Lesson**: Never flash partition images directly via MTD block devices on RK3188 devices. Always use the USB flashing method.

### Trying to use rkflashtool for everything

`rkflashtool` is great for reading and writing flash partitions over USB, but it cannot write the bootloader. The RC4-encrypted IDB format and the multi-copy write strategy require `upgrade_tool`. These are not interchangeable tools.

---

## The Unbreakable Safety Net

The thing that saved the device was something I didn't know existed beforehand: the RK3188's Mask ROM mode. Every Rockchip SoC has an immutable ROM that runs before any external code. If the bootloader on NAND/eMMC is corrupted or missing, the chip falls back to this ROM and exposes a USB interface for recovery.

As long as:
- The chip itself is physically intact
- You have a USB cable and a PC running Linux

...the device is never truly bricked. You can always recover it.

---

## Resources

All the files needed for flashing (bootloader binary, parameter file) are in the [mk809iii GitHub repo](https://github.com/radzki/mk809iii/tree/master/android). The original 519MB firmware package is attached to the [v1.0-android release](https://github.com/radzki/mk809iii/releases/tag/v1.0-android).

---

*The full flashing procedure with exact commands is documented in the [README](https://github.com/radzki/mk809iii#flashing-stock-android).*
