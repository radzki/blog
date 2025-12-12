---
layout: post
title: "Reverse Engineering Sagemcom F@ST 5302 (GVT/VIVO)"
description: "Getting root shell access on the Sagemcom F@ST 5302 router via UART"
date: 2021-01-14
tags: [router, embedded, uart]
---

## Introduction

I had an old [Sagemcom F@ST 5302](https://www.manualslib.com/products/Sagemcom-F-St-5302-9140809.html) router collecting dust — a hand-me-down from a friend. When I needed a spare router for a lab network and my usual one was tied up in another project, I decided to give it a shot. What started as a quick setup turned into an interesting reverse engineering session.

My first instinct with any embedded system: look for a UART interface.

---

## Locating the UART

Opening the router and inspecting the PCB, you'll find a 4-pin UART header. The layout from front to back is roughly:

```
┌─────────────────────────────┐
│  LEDs (front of router)     │
├─────────────────────────────┤
│  CPU heat sink              │
├─────────────────────────────┤
│  UART header (4 pins):      │
│    • RX                     │
│    • TX                     │
│    • GND                    │
│    • 3.3V                   │
├─────────────────────────────┤
│  Ethernet ports (back)      │
└─────────────────────────────┘
```

---

## Connecting to UART

Use a USB-to-TTL adapter (or an Arduino with RST shorted to GND) to connect to the UART pins. Then open a serial session:

```console
screen -L /dev/ttyUSB0 115200
```

The `-L` flag enables logging, which is useful for capturing boot messages and debugging output.

---

## Escaping the Restricted Shell

Once connected, you'll get a TTY — but you'll quickly notice that most standard commands are blocked. The router runs a restricted shell that filters or suppresses output from common binaries.

The trick is to chain a command that _is_ allowed (like `ping`) with `bash`. Since the shell executes the entire line, we can break out of the restricted environment:

```console
ping 8.8.8.8 -c 1 > /dev/null 2>&1; bash
```

This spawns a proper bash shell — with root privileges.

---

## Disabling the Firewall for Remote Access

The default firewall rules block incoming connections. If you want to enable Telnet for more convenient remote access (instead of relying on the serial connection), flush the iptables rules:

```console
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -F
iptables -X
```

---

## Obtaining Credentials

There are two ways to get the admin password:

1. **Crack the hash** in `/etc/passwd` using John the Ripper (time-consuming)
2. **Inspect the web interface source** — the password is exposed in the HTML (easy)

The credentials:

```
superadmin:1234567gvt
```

---

## Boot Log Reference

Here's the CFE bootloader output for reference. This confirms we're dealing with a BCM6328-based device:

```console
CFE version 7.222.1 for BCM96328 (32bit,SP,BE)
Build Date: Wed Apr  3 15:07:05 CST 2013 (cookiechen@SZ01007.DONGGUAN.CN)
Copyright (C) 2005-2012 SAGEMCOM Corporation.

HS Serial flash device: name ID_W25X64, id 0xef17 size 8192KB
Total Flash size: 8192K with 2048 sectors
Chip ID: BCM6328B0, MIPS: 320MHz, DDR: 320MHz, Bus: 160MHz
Main Thread: TP0
Memory Test Passed
Total Memory: 67108864 bytes (64MB)
Boot Address: 0xb8000000

Board IP address                  : 192.168.1.1:ffffff00
Host IP address                   : 192.168.1.100
Gateway IP address                :
Run from flash/host (f/h)         : f
Default host run file name        : vmlinux
Default host flash file name      : bcm963xx_fs_kernel
Boot delay (0-9 seconds)          : 1
Board Id (0-4)                    : F@ST5302V2
Primary AFE ID OVERRIDE           : 0x00000001
Bonding AFE ID OVERRIDE           : 0x00000002
Number of MAC Addresses (1-32)    : 11
Base MAC Address                  : 2c:39:96:f7:ae:14
PSI Size (1-64) KBytes            : 40
Enable Backup PSI [0|1]           : 0
System Log Size (0-256) KBytes    : 64
Main Thread Number [0|1]          : 0
Voice Board Configuration (0-0)   : LE89116

*** Press any key to stop auto run (1 seconds) ***
```

---

## Useful CLI Commands

Once you have shell access, here are some handy commands for configuring the router:

### WAN Configuration

```console
# Delete existing WAN service
wan delete service eth3.0

# Add new WAN service with IPoE
wan add service eth3 --protocol ipoe --firewall disable --nat enable --igmp enable --dhcpclient enable

# View/set default gateway
defaultgateway show
defaultgateway config eth3.0

# Set static DNS
dns config static 8.8.8.8 8.8.4.4
```

### Client-Side Routing (if needed)

If your client machine isn't routing traffic correctly through the router:

```console
sudo ip route add 192.168.2.0/24 via 192.168.25.1 dev wlp2s0
```

---

## Removing the Wi-Fi Speed Limit

The ISP firmware artificially limits Wi-Fi to 10 Mbps. To remove this restriction and set your preferred channel:

```console
wlctl down
wlctl rate -1
wlctl rateset default
wlctl channel 11
wlctl up
```

---

## Current Limitations

I got the router working as a Wi-Fi access point, receiving internet via WAN (IPoE) and bridging it to wireless clients. Not bad for a device that was headed for the trash.

However, there's a significant limitation: **all configuration is lost on reboot**. We don't have persistent write access to the firmware. Possible next steps:

- Extract the firmware via JTAG
- Look for a way to modify the flash directly
- Investigate the CFE bootloader for firmware dump capabilities

---

## Edit (2025)

While revisiting my old posts, with my knowledge now, I can safely say that we could easily extract the firmware either via UART (using CFE's built-in dump commands) or by reading the flash chip directly with a CH341A programmer, for example.

---

## References

- [Reverse Engineering F@ST 2704](https://github.com/Mixbo-zz/FaST2704)
- [ZyXEL CLI Reference (wan commands)](<ftp://ftp.zyxel.fr/ftp_download/P-660HN-51/firmware/P-660HN-51_1.12(AADW.7)C0_2.pdf>)
- [BCM CLI Reference (Chinese)](http://bbs.mydigit.cn/simple/?t1478045.html)
- [CLI Command Source Code](https://github.com/ad7843/hi/blob/master/cli_cmd.c)
- [wlctl Command Reference](http://ahmedfarazch.blogspot.com/2013/11/ptcltenda-w150d-and-micronet-sp3367nl.html)
- [CFE Firmware Dump Tool](https://github.com/openwrt-es/cfe-backup/blob/master/cfetool.py)
- [OpenWrt Forum: Dumping Router Images](https://forum.archive.openwrt.org/viewtopic.php?id=55648)
- [Restricted Shell Escape Techniques](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
