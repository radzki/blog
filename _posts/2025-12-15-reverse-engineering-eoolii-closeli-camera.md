---
layout: post
title: "Reverse Engineering the Eoolii Smart Camera: From Cloud-Dependent to Fully Local"
description: "A deep dive into reverse engineering a Chinese IoT camera, bypassing cloud dependencies, and building a local streaming solution with multi-camera support"
date: 2025-12-15
tags: [embedded, firmware, iot, reverse-engineering, frida, security]
---

## Introduction

When I purchased a pair of Eoolii smart cameras (also sold under Closeli/Taismart brands), I didn't expect to spend months reverse engineering their entire communication stack. But when I figures the cameras were not ONVIF compatible, and the Chinese cloud servers started experiencing outages making the cameras become paperweights, I decided to take matters into my own hands.

This post documents the complete journey of reverse engineering these cameras—from initial network reconnaissance to firmware extraction, mobile app analysis, protocol decryption, and ultimately building a fully local streaming solution that works without any cloud dependency.

**The Goal**: Transform cloud-dependent cameras into locally-controlled devices that can stream directly to my Frigate NVR.

**The Result**: A complete local infrastructure that replaces all Chinese cloud services, supports multiple cameras simultaneously, and can be deployed via Docker.

---

## Part 1: Initial Reconnaissance

### The Target

- **Camera**: [Eoolii/Closeli IP Camera](https://device.report/manual/16921413)
- **SoC**: Allwinner XR872 (ARM Cortex-M RTOS)
- **Mobile App**: com.taismart.global (Eoolii) v6.1107.0.9824
- **Cloud Infrastructure**: Multiple Chinese servers (closeli.com, icloseli.com)

### Setting Up the Network Lab

The first step was establishing visibility into all network traffic. I set up a dedicated network lab on my Kali Linux machine:

```
Camera (WiFi) ──┐
                ├──> WiFi Router (eth1) ──> Kali Linux (MITM/Analysis)
Smartphone ─────┘
```

Key components:
- **dnsmasq**: DHCP server and DNS forwarder
- **Wireshark/tcpdump**: Packet capture
- **mitmproxy/Burp Suite**: HTTPS interception

### Discovering the Architecture

Initial packet captures revealed the camera uses a **three-channel architecture**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    CAMERA COMMUNICATION                         │
├─────────────────────────────────────────────────────────────────┤
│  1. XMPP/WebSocket (Control/Signaling)                         │
│     └─ Servers: 119.8.85.245:50021, :50031                     │
│     └─ Purpose: App ↔ Camera coordination                      │
│                                                                 │
│  2. TCP Relay Server (Video Stream)                            │
│     └─ Server: Dynamically assigned (101.44.202.119:50721)     │
│     └─ Protocol: TLS + AES-GCM encrypted MJPEG                 │
│                                                                 │
│  3. HTTPS API (Management)                                     │
│     └─ Servers: auto-link.closeli.com, esd.icloseli.com        │
│     └─ Purpose: Service discovery, config, updates             │
└─────────────────────────────────────────────────────────────────┘
```

This was the first major insight: the camera doesn't stream directly. Instead, it connects to a relay server, the app connects to the same relay, and the relay bridges them together. The XMPP server coordinates which app connects to which camera on which relay.

---

## Part 2: Hardware Analysis - Firmware Extraction

### UART Access

The camera PCB exposed UART test points. Using a USB-TTL adapter and `picocom`:

```bash
picocom -b 115200 --omap crlf --imap lfcrlf /dev/ttyUSB0
```

This provided access to the camera's CLI, revealing valuable information:
- WiFi configuration commands (`net sta config`)
- Flash operations (`flash read`, `flash write`)
- System info (`sysinfo`)
- Factory test mode (`etf`)

### Flash Dump Extraction

Using a CH341A programmer, I extracted the 8MB SPI NOR flash:

**Flash Chip**: Puya P25AQ64SH (8MB SPI NOR)

```bash
# Verify extraction integrity
md5sum camera_flash_dump.bin  # Extracted 3 times, all matching
```

### Flash Layout Analysis

The flash uses the AWIH (Allwinner/XRadio Image Header) bootloader format:

```
┌─────────────────────────────────────────────────────────────┐
│ 0x000000 - 0x010000 (64KB)   │ Bootloader (AWIH)           │
├─────────────────────────────────────────────────────────────┤
│ 0x010000 - 0x080000 (448KB)  │ Firmware Partition 1        │
├─────────────────────────────────────────────────────────────┤
│ 0x080000 - 0x100000 (512KB)  │ Firmware Partition 2        │
├─────────────────────────────────────────────────────────────┤
│ 0x100000 - 0x200000 (1MB)    │ Firmware Partition 3        │
├─────────────────────────────────────────────────────────────┤
│ 0x200000 - 0x400000 (2MB)    │ Data Partition              │
├─────────────────────────────────────────────────────────────┤
│ 0x400000 - 0x600000 (2MB)    │ Erased/Empty Region         │
├─────────────────────────────────────────────────────────────┤
│ 0x600000 - 0x800000 (2MB)    │ Configuration/Data Storage  │
└─────────────────────────────────────────────────────────────┘
```

### The YAFFS False Positive Trap

Binwalk initially detected 245+ "YAFFS filesystem" entries:

```bash
$ binwalk camera_flash_dump.bin
# ... 245+ YAFFS entries ...
```

I spent considerable time trying various YAFFS extraction tools:
- `unyaffs` / `unyaffs2` - Failed
- `yaffshiv` - Failed
- Custom Python parser - Failed

**The lesson learned**: These were false positives! The XR872 RTOS uses custom data structures that happen to match YAFFS object header patterns but aren't actual filesystems. This is common with embedded RTOS platforms that use direct flash access rather than traditional filesystems.

### Intelligence Gathering via Strings

The most productive approach was simple string extraction:

```bash
# Network infrastructure
strings camera_flash_dump.bin | grep -E "http://|https://"
strings camera_flash_dump.bin | grep -E "\.(com|net|org|cn)"

# API endpoints discovered:
# https://%s/sentry/dns/camera/services
# https://%s/lookup/v6/assignRelayIp
# https://%s/ntp

# Domains discovered:
# auto-link.closeli.cn
# auto-link.closeli.com
# esd.icloseli.com
```

I also extracted 63 PEM certificates embedded in the firmware, revealing the camera's trusted CAs and TLS configuration. I did not use them for anything, though. Heheh.

---

## Part 3: Mobile App Reverse Engineering

### Static Analysis with JADX

Decompiling the APK revealed the app's structure:

```bash
jadx -d output_dir com.taismart.global.apk
```

Key findings in the Java code:
- **XmppDef.java**: Complete list of XMPP command codes
- **EncryptUtils.java**: Encryption utilities (though not used for video)
- Native libraries: `libtcpbuffer.so`, `libmv3_sourceparser.so`

### The Double Encryption Discovery

Initial attempts to decrypt captured traffic failed. Even after TLS decryption using captured session keys, the video data remained encrypted. This led to the critical discovery:

**The camera uses double encryption:**

1. **Layer 1 - TLS**: Standard TLS 1.2/1.3 transport encryption
2. **Layer 2 - AES-GCM**: Application-layer encryption using WolfSSL

### Dynamic Analysis with Frida

To understand the encryption, I used Frida to hook into the running app:

```javascript
// Hook WolfSSL decryption function
Interceptor.attach(Module.findExportByName("libtcpbuffer.so", "wc_AesGcmDecrypt"), {
    onEnter: function(args) {
        console.log("[*] wc_AesGcmDecrypt called");
        console.log("    Key: " + hexdump(args[1], {length: 16}));
        console.log("    IV: " + hexdump(args[4], {length: 12}));
    },
    onLeave: function(retval) {
        console.log("    Decrypted data available");
    }
});
```

### Captured Encryption Details

- **Algorithm**: AES-GCM (Galois/Counter Mode)
- **Key Size**: 128-bit (16 bytes)
- **Library**: WolfSSL (wolfCrypt)
- **IV Structure**: 12 bytes - [4-byte timestamp][8-byte incremental counter]

Example captured session keys:
```
3c5b990f746d947b5d8b1ed818d0f9b2
5a8615f93c7e0db375a2033be1aea24e
211f593eec4a542fc3cfeebaabf96a7a
```

### Video Format Discovery

After decryption, the video stream structure became clear:

```
[35-byte protobuf header][JPEG data starting with FFD8]
```

The video format is **Motion JPEG (MJPEG)** - each frame is a complete JPEG image, making extraction trivial once decrypted.

---

## Part 4: Protocol Reverse Engineering

### XMPP Command Reference

By analyzing `XmppDef.java`, I documented the complete command set:

| Code | Name | Purpose |
|------|------|---------|
| 1792 | Request_Get | Get camera settings/status |
| 1793 | Request_Set | Set camera settings |
| 1829 | Request_DoRebootDevice | Reboot camera |
| 222 | Subrequest_GETSDCARDSTATUSINFO | Start live view |

### The CCAM Media Protocol

The video stream uses a custom protocol called "CCAM" (version 4):

```
┌─────────────────────────────────────────────────────┐
│ Offset │ Length │ Description                       │
├─────────────────────────────────────────────────────┤
│ 0      │ 4      │ Packet Length (Big Endian)        │
│ 4      │ 4      │ Magic: 'CCAM'                     │
│ 8      │ 1      │ Version: 0x04                     │
│ 9      │ 1      │ Type: 0x02=Video, 0x01=Audio      │
│ 10     │ 4      │ Reserved                          │
│ 14     │ 1      │ Total Fragments                   │
│ 15     │ 1      │ Fragment Number (1-based)         │
│ 16     │ 2      │ Frame ID                          │
│ 28     │ N      │ Payload (Media Data)              │
└─────────────────────────────────────────────────────┘
```

**Video**: MJPEG, unencrypted after CCAM decapsulation
**Audio**: G.711 A-law, 8000 Hz, mono, 320-byte packets (40ms each)

### The Relay Protocol

When connecting to the relay, the camera sends JSON-wrapped protobuf messages:

**GDL (Get Device List)** - Camera polls: "Is anyone trying to connect?"
```json
{
  "action": "GDL",
  "data": {
    "deviceId": "xxxxS_AABBCCDDEEFF",
    "useremail": "user@example.com",
    "apiVersion": "1.0",
    "accessKey": "xxxxxxxx-xxx",
    "signature": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
  }
}
```

**UDI (Update Device Info)** - Status updates:
```json
{
  "action": "UDI",
  "data": {
    "deviceId": "xxxxS_AABBCCDDEEFF",
    "modelId": "IH_IPC_XR872_01",
    "productKey": "xxxxxxxx-xxx",
    "services": "{\"1\":\"1.6.3.9035\",\"2\":\"1.6.3.9035\"}"
  }
}
```

---

## Part 5: Building the Local Infrastructure

### DNS Redirection

The first step was redirecting all camera traffic to my local server using dnsmasq:

```conf
# /etc/dnsmasq.conf
address=/auto-link.closeli.com/192.168.1.100
address=/auto-link.closeli.cn/192.168.1.100
address=/esd.icloseli.com/192.168.1.100
address=/closeli.com/192.168.1.100
address=/icloseli.com/192.168.1.100
```

### Mock API Server

I built a Python HTTPS server to replace all Chinese API endpoints:

```python
# mock_api_server.py - Key endpoints

# Service discovery
@route('/sentry/dns/camera/services')
def service_discovery():
    return {
        "code": "200",
        "data": {
            "addresses": [
                {"service_name": "doorbell_server_ip", "url": f"{LOCAL_IP}:50721"},
                {"service_name": "lecam_purchase_server_ip", "url": LOCAL_IP}
            ]
        }
    }

# Relay assignment
@route('/lookup/v6/assignRelayIp')
def relay_assignment():
    return {
        "failflag": "0",
        "relayhost": LOCAL_IP,
        "relayport": "50721"
    }
```

### Local Relay Server

The heart of the system is the relay server that bridges camera and client connections:

```python
# local_relay_server.py - Core architecture

SESSIONS = {}  # Keyed by device_id

class Session:
    camera_conn = None      # Camera's control connection
    camera_stream = None    # Camera's video stream
    app_conn = None         # App/client connection
    app_stream = None       # App's receiving stream
```

Key features:
- TLS encryption (camera requires it)
- XMPP message parsing and response
- CCAM video stream bridging
- Multi-camera support via session registry

### Stream Server

The stream server connects to the relay as an "app" and exposes HTTP endpoints:

```python
# stream_server.py

# Connect to relay, authenticate, trigger stream
def connect_to_camera(device_id):
    # 1. TLS handshake
    # 2. Send CCAM login with device_id
    # 3. Send XMPP TIMELINE_QUERY to trigger stream
    # 4. Receive and decode CCAM packets

# HTTP endpoints
# GET /camera/video - MJPEG stream
# GET /camera/audio - WAV audio stream (G.711 A-law)
```

---

## Part 6: Multi-Camera Support

### The Challenge

Initially, the solution only supported one camera. With two cameras on my network, I needed proper session isolation.

### Session Registry

Instead of global connection variables, I implemented a session registry:

```python
SESSIONS = {
    "xxxxS_AABBCCDDEEFF": {
        "camera_control": <socket>,
        "camera_stream": <socket>,
        "app_conn": <socket>,
        "app_stream": <socket>,
        "app_login_info": {...}
    },
    "xxxxS_112233445566": {
        # ... second camera
    }
}
```

### Management Interface

I added a TCP management interface for monitoring and control:

```bash
# List connected cameras
$ python relay_cli.py list
Connected Sessions:
  [1] xxxxS_AABBCCDDEEFF
      Camera Control: Yes
      Camera Stream: Yes
      App Connected: No

# Trigger stream for specific camera
$ python relay_cli.py trigger xxxxS_AABBCCDDEEFF

# Reboot camera
$ python relay_cli.py reboot xxxxS_AABBCCDDEEFF
```

---

## Part 7: Docker Deployment

### Containerization

For easy deployment, I created Docker configuration:

```yaml
# docker-compose.yml
version: '3.8'

services:
  relay:
    build: .
    ports:
      - "50721:50721"  # Relay
      - "50722:50722"  # Management
    volumes:
      - ./server.crt:/app/server.crt
      - ./server.key:/app/server.key
      - ./.env:/app/.env

  api:
    build: .
    command: python3 mock_api_server.py
    ports:
      - "443:443"

  stream-camera1:
    build: .
    command: python3 stream_server.py --device_id ${CAMERA1_DEVICE_ID} --port 8081
    ports:
      - "8081:8081"
    profiles:
      - camera1
```

### Usage

```bash
# Start core services
docker-compose up -d relay api

# Start stream servers for cameras
docker-compose --profile camera1 --profile camera2 up -d

# Access streams
# Camera 1: http://localhost:8081/camera/video
# Camera 2: http://localhost:8082/camera/video
```

---

## Part 8: Integration with Frigate NVR

The final step was integrating with Frigate for object detection and recording:

```yaml
# frigate.yml
cameras:
  front_door:
    ffmpeg:
      inputs:
        - path: http://stream-server:8081/camera/video
          roles:
            - detect
            - record
    detect:
      width: 1280
      height: 720
      fps: 5
```

---

## Security Analysis

### Strengths of Original Implementation

- Double encryption (TLS + AES-GCM)
- Session-specific keys (change per connection)
- Proper authenticated encryption (GCM mode with AEAD)
- Incremental IVs (prevents IV reuse)

### Weaknesses Discovered

- **No Certificate Pinning**: Self-signed certificates accepted, enabling MITM
- **Keys Extractable**: Runtime memory inspection via Frida exposes session keys
- **Relay Architecture**: All video routes through third-party Chinese servers
- **No Local Option**: Original firmware has no local streaming capability

---

## Tools Summary

### Successful Tools

| Tool | Purpose | Result |
|------|---------|--------|
| Wireshark/tcpdump | Network capture | Revealed three-channel architecture |
| Frida | Runtime hooking | Captured AES-GCM keys, traced decryption |
| friTap | TLS key extraction | Enabled Wireshark TLS decryption |
| JADX | APK decompilation | Revealed XMPP command codes |
| binwalk | Firmware analysis | Extracted PEM certificates |
| strings | Intelligence gathering | Found API endpoints, domains |
| picocom | UART access | Live system debugging |
| CH341A | Flash extraction | 8MB firmware dump |

### Failed Approaches

| Tool | Attempted | Why It Failed |
|------|-----------|---------------|
| unyaffs/yaffshiv | YAFFS extraction | XR872 doesn't use YAFFS |
| mount/losetup | Filesystem mount | No mountable filesystem |
| Standard crypto analysis | Decrypt video | Missed second AES-GCM layer |

---

## Lessons Learned

### 1. IoT Devices Often Use Multiple Encryption Layers

Initial TLS decryption wasn't enough. Always verify decrypted data makes sense before assuming success.

### 2. Embedded RTOS != Linux

Standard forensics tools for Linux filesystems don't apply. Focus on UART access and live system analysis instead of offline extraction.

### 3. Mobile App Analysis is Often More Productive

The APK contained the complete protocol specification in decompiled Java code. Native library hooking with Frida revealed encryption keys and data flows that would have taken weeks to discover through firmware analysis alone.

### 4. Document Everything

The three-channel architecture wasn't obvious from any single analysis method. Only by correlating UART logs, network captures, and app decompilation did the full picture emerge.

### 5. Cloud Outages Are a Feature, Not a Bug

The Chinese server outage that broke my cameras ultimately forced me to build a superior local solution with better privacy, lower latency, and no cloud dependency.

---

## Conclusion

What started as frustration with unreliable cloud servers turned into a comprehensive reverse engineering project. The result is a fully local camera system that:

- Works without internet connectivity
- Supports multiple cameras simultaneously
- Integrates with Frigate NVR for AI-powered detection
- Can be deployed via Docker for easy setup
- Provides complete control over all camera functionality

The cameras that were once dependent on Chinese cloud servers now run entirely on my local network, with all traffic under my control.

---

## Files and Resources

You can find useful files, specially for setting up the stream locally and also the camera firmware dump, here: https://github.com/radzki/CloseliStreamServer


## Future work
 
While investigating the firmare, I could see some interesting strings such as the ones below, which suggests the camera might have RTSP support, after all. But I would need to figure out how to patch the function to enable it and reflash the firmware.
```
└─$ strings 21cc00_app_xip_execute-in-place.bin | grep rtsp
rtsp_thread_create[%s].
rtsp_thread_create
%x: will release rtsp2mp4mgr...
%x: release rtsp2mp4mgr end
```


---

*This project was conducted for personal use and educational purposes. Always ensure you have appropriate authorization before reverse engineering commercial products.*
