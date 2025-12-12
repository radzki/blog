---
layout: post
title: "Reverse Engineering Philco PH32B51DSGWVB Smart TV"
description: "Modifying the firmware of a budget Smart TV to run SS-IPTV"
date: 2021-01-15
tags: [embedded, firmware, smart-tv]
---

## Introduction

The goal: install [SS-IPTV](https://ss-iptv.com/) on my grandpa's old Philco smart TV so he could watch IPTV streams (m3u/m3u8) during the pandemic. Simple enough, right?

The TV's built-in app store is essentially dead — most apps no longer work. But the hardware is still functional. Time to dig into the firmware.

---

## Obtaining the Firmware

Philco provides firmware downloads on their website:
[https://www.philco.com.br/site_o/index.php/indexs/drivers/](https://www.philco.com.br/site_o/index.php/indexs/drivers/)

Enter your serial number and download the `.bin` file.

---

## Extracting the Firmware

Running `binwalk` on the firmware file:

```console
$ binwalk PH32B51DSGWVB.orig.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             POSIX tar archive, owner user name: "img"
```

Surprisingly simple — it's just a tar archive. Extract it:

```bash
#!/bin/bash
mkdir PH32B51DSGWVB && cd PH32B51DSGWVB && tar -xvf ../$1
```

The archive contents:

```
0.vmlinux.rescue.bin  checksum.exe  customer     font.ttf   mkfs.jffs2     ...
busybox               config.txt    flash_erase  install_a  mkyaffs2image  ...
```

After some investigation, the interesting file is `squashfs1.img` inside the `package2` directory:

```console
$ binwalk package2/squashfs1.img

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Squashfs filesystem, little endian, version 4.0, compression:gzip, size: 99022797 bytes, 2588 inodes, blocksize: 131072 bytes
```

Extract the SquashFS filesystem:

```console
$ unsquashfs package2/squashfs1.img
$ ls squashfs-root/

bin  dev  etc  lib  mnt  proc  sbin  sys  tmp  tmp_orig  usr  var
```

Now we have access to the TV's root filesystem.

---

## Understanding the UI Framework

The files in `/usr/local/bin/dfbApp/qt/Resource/ui_script/TV036_1_ISDB` are particularly interesting. The TV's UI is built using RSS-like XML files with embedded Lua scripts.

For example, `NetworkPage.rss` defines the network apps menu:

```xml
<?xml version='1.0' ?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">
<onEnter>
    if (Misc_IsYoutubeEnable() == "TRUE") {
        subItemList = pushBackStringArray(subItemList, "$[YOUTUBE]");
        subItemImage = pushBackStringArray(subItemImage, ".../Network/YOUTUBE.png");
        itemSize = itemSize + 1;
    }

    if (Misc_IsPicasaEnable() == "TRUE") {
        subItemList = pushBackStringArray(subItemList, "$[PICASA]");
        subItemImage = pushBackStringArray(subItemImage, ".../Network/PICASA.png");
        itemSize = itemSize + 1;
    }

    <!-- ... more services ... -->
</onEnter>

<onUserInput>
    if(select == "$[YOUTUBE]") {
        Misc_SwitchToYoutube();
    }
    else if(select == "$[PICASA]") {
        Misc_SwitchToPicasa();
    }
    <!-- ... more handlers ... -->
</onUserInput>
</rss>
```

Each service has a corresponding `Misc_SwitchTo*()` function. My initial plan: replace `Misc_SwitchToPicasa()` with a call to load SS-IPTV instead.

But what binary actually parses these files and calls these functions?

---

## Finding the Main Binary

After digging through the filesystem, I found the core application: **DvdPlayer** (yes, really — that's what they named the main TV application).

This binary handles everything: TV tuning, app launching, UI rendering, and more.

Searching for Picasa-related strings:

```console
$ strings DvdPlayer | grep -i PICASA

-------------------- Picasa Slideshow ------------------
Picasa_StartSlideshow
Picasa_EndSliderShow
Picasa_GetSignature
Picasa_SetToken
Picasa_GetToken
Picasa_SetUserID
Picasa_GetUserID
/tmp/www/Picasa
http://localhost/Picasa/picasa_login.html
Misc_IsPicasaEnable
Misc_SwitchToPicasa
```

Running `binwalk` on the binary confirms it's a 32-bit MIPS executable:

```console
$ binwalk DvdPlayer

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             ELF, 32-bit LSB MIPS64 executable, MIPS, version 1 (SYSV)
...
12542764      0xBF632C        Unix path: /usr/local/etc/dvdplayer/dtv_channel.txt
12576836      0xBFE844        Unix path: /etc/dvdplayer/script
...
```

The output reveals paths to configuration files, SSL libraries, network settings, and more — a goldmine of information about the system's internals.

---

## Decompiling with Ghidra

Using [Ghidra](https://ghidra-sre.org/) to decompile and analyze the binary, I located the Picasa-related functions. The TV uses a browser called `qjyBrowser` (located at `/usr/local/bin/dfbApp/qjyBrowser`) to render web-based apps.

My plan: replace the Picasa login URL in `Misc_SwitchToPicasa()` (found in the `.data` segment of DvdPlayer) with the SS-IPTV URL (`https://app.ss-iptv.com/`).

---

## Repacking the Firmware

After modifying the binary, repack the SquashFS image:

```bash
#!/bin/bash
# Run inside package2 directory
rm squashfs1.img
sudo chown -R root:root squashfs-root/
mksquashfs squashfs-root/ squashfs1.img
sudo rm -rf squashfs-root
```

Then repack the entire firmware archive:

```bash
#!/bin/bash
cd PH32B51DSGWVB
pax -wf ../PH32B51DSGWVB.bin *
```

Copy the modified firmware to a USB drive and flash it via the TV's recovery menu.

---

## First Attempt: Failure

The firmware flashed successfully, but SS-IPTV didn't work. The `qjyBrowser` is too old and incompatible with the SS-IPTV web app.

But wait — YouTube still works on this TV. How?

Back to Ghidra.

---

## Discovering the Qt Browser

Further investigation revealed that YouTube uses a _different_ browser — a Qt-based one:

```
SwitchToYoutube()

execQtTestBrowser.sh -useragent %s -no-loading-status -remote-inspector-port 9222 -service-type youtube http://www.youtube.com/tv
```

Flickr also uses this Qt browser. So instead of hijacking Picasa (which uses the older `qjyBrowser`), I'll hijack Flickr:

```
SwitchToFlickr()  →  Modified to load SS-IPTV

execQtTestBrowser.sh -useragent %s -no-loading-status -remote-inspector-port 9222 -service-type youtube http://app.ss-iptv.com/
```

I kept YouTube intact since my grandpa actually uses it.

---

## Second Attempt: JavaScript Compatibility Issues

Repacked and flashed. Still doesn't work.

SS-IPTV's JavaScript requires:

1. **MAC address access** — the TV's browser doesn't expose this
2. **`window.history` API** — not supported by the Qt browser

The solution: host a modified version of SS-IPTV locally. Conveniently, the TV runs a lightweight HTTP server with CGI support — perfect for serving patched JavaScript.

---

## Patching the JavaScript

### Stubbing the history API

```javascript
this._deviceInfoInterface.history = function () {
  return [];
};
```

### Hardcoding the MAC address

```javascript
prepareMAC: function (a) {
    if (null == a || "" == a) return "00:00:00:00:00:00";
    // ... MAC formatting logic ...
},
get_netWiredMAC: function () {
    var a;
    a = null == this._deviceInfoInterface
        ? "00:00:00:00:00:00"
        : this._deviceInfoInterface.get(18);
    "" != f.getArgumentValue("wiredMAC") && (a = f.getArgumentValue("wiredMAC"));
    return this.prepareMAC(a);
},
get_netWirelessMAC: function () {
    return this.prepareMAC(
        null == this._deviceInfoInterface
            ? "00:00:00:00:00:00"
            : this._deviceInfoInterface.get(19)
    );
}
```

The modified JS bundle is placed in the TV's HTTP server root:

```console
$ ls tmp_orig/www/

index.html  tv.js
```

---

## Final Result

Repack, flash, and...

![SS-IPTV running on the Philco TV](https://i.ibb.co/m4Jxxb1/efece87a-17ba-40e6-89e1-ac80c5fc942f.jpg)

**It works!**

The UI is sluggish (this is old hardware, after all), but video playback is smooth. Mission accomplished.

---

## Conclusion

What started as a simple "install an app for grandpa" turned into a deep dive into:

- Firmware extraction and repacking (tar + SquashFS)
- Reverse engineering a MIPS binary with Ghidra
- Understanding a proprietary RSS/Lua-based UI framework
- Patching JavaScript to work around missing browser APIs

The TV is now happily serving IPTV streams. Not bad for hardware that was essentially abandoned by its manufacturer.
