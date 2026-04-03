---
layout: post
title: "Closeli Camera Part 2: Cracking the Remote Relay (Or: How a Missing Empty String Cost Me Weeks)"
description: "Reverse engineering libtcpbuffer.so with Ghidra MCP to find why the Chinese relay was silently dropping our protobuf auth — and discovering the embarrassingly simple root cause"
date: 2026-04-03
tags: [embedded, iot, reverse-engineering, ghidra, frida, security, protobuf]
---

## Introduction

In the [previous post]({% post_url 2025-12-15-reverse-engineering-eoolii-closeli-camera %}), I built a fully local replacement for the Closeli camera's Chinese cloud infrastructure. The cameras now stream directly to my Frigate NVR via a local relay server, bypassing all cloud dependencies.

But there was one thing bothering me: the local relay requires the camera and client to be on the same LAN. What about remote access?

The Chinese app uses a relay system where both the camera and the phone connect to a server in China, and the server bridges them. The camera is always connected to its assigned relay. If I could connect *my* client to that same relay — without kicking off the phone app — I'd have remote video access while still controlling the camera through the official app.

**The Goal**: Receive the camera's video feed directly from the Chinese relay server, without disrupting the app's control channel.

**The Journey**: Weeks of debugging what looked like a WebSocket framing problem, until Ghidra proved it was never a WebSocket problem at all — and then finding a one-line encoding bug that had been silently corrupting every single attempt.

---

## Background: What Was Already Known

From the previous post, the relay protocol was mostly mapped out:

```
┌──────────────────────────────────────────────────────────┐
│              RELAY PROTOCOL (from MITM + Frida)          │
├──────────────────────────────────────────────────────────┤
│  Connection 1 — Control Auth (type=6)                    │
│    Raw TLS → 4-byte length + protobuf Request            │
│    Sets up session, carries XMPP messages                │
│                                                          │
│  Connection 2 — Data (type=2)                            │
│    Raw TLS → 4-byte length + protobuf Request            │
│    Carries MediaPackage video/audio frames                │
└──────────────────────────────────────────────────────────┘
```

Frida had already captured the exact protobuf the app sends for type=6 auth (hooking `wolfSSL_write` inside `libtcpbuffer.so`). The relay responded with a 63-byte protobuf back to the app, containing `result=0` and a session token.

But when I sent the same bytes from Python, the relay closed the connection every time. Silently. No error. Just EOF.

The working assumption: the relay must be looking for WebSocket framing around the protobuf. After all, the wsrelay endpoint is `esd.icloseli.com:443` — an HTTPS server. Surely it expects WebSocket binary frames?

---

## Part 1: The WebSocket Red Herring

I spent considerable time trying variations of WebSocket framing:

| Attempt | Result |
|---------|--------|
| Python `websockets` library, binary frame | Timeout (server silent) |
| Manual masked binary frame (0x82 + mask) | Timeout |
| Manual unmasked binary frame | "not masked" error |
| TEXT frame containing protobuf | JSON parse error |
| Different TLS SNI values | No change |

The JSON login over WebSocket did work: send `{"type":1, "token":"...", "deviceid":"ANDRC_xxx"}` as a TEXT frame and get `{"result":0,"xmppSupport":true}` back. But the binary protobuf frames were consistently ignored.

At some point I got lucky and saw a 63-byte response from the server — the exact size of the auth response Frida had captured from the real app. But only with the correct masked binary WS framing? Or only sometimes? The logging wasn't good enough to be sure.

This is where the investigation stalled.

---

## Part 2: Ghidra MCP — Static Analysis at Scale

With the dynamic approach stuck, I switched to static analysis. The native library `libtcpbuffer.so` contains all the relay logic, and I had it loaded in Ghidra. What I hadn't tried was methodically tracing the code path from "app wants to connect" to "protobuf gets sent."

I set up **GhidraMCP** — a bridge that exposes Ghidra's decompiler via MCP (Model Context Protocol), letting an AI assistant query functions, decompile code, and cross-reference strings directly from the conversation. With Ghidra running with the `libtcpbuffer.so` project open, queries like "decompile `TCPBufferCBWebSocketCommonProc`" or "list all strings containing 'websocket'" returned decompiled C pseudo-code within seconds.

This changed the pace dramatically. Instead of waiting minutes to navigate Ghidra's GUI, I could trace call chains in bulk.

---

## Part 3: Following the Trail

The key question was: **where does the protobuf actually get sent?**

Starting from the main loop:

```
LoopReadProc → NonBlockingReadWriteProc → InteractWithServer
```

`InteractWithServer` was the critical function. Inside it, there's a branch on `this + 0x8c` — a boolean flag. When it's 1, we're in "WebSocket relay mode." When it's 0, we're in "raw relay mode."

Here's the surprising part: **both branches call `NonBlockingSSLWrite` → `wolfSSL_write`**.

There's no WebSocket frame construction happening here. The protobuf goes straight into the TLS socket either way.

The confirmation came from `SetRelayMessageRequestCmd` — the function that builds the type=6 protobuf. It assembles the message and passes it to `NonBlockingSSLWrite`. No WS framing. No intermediate layer. Raw TLS.

And then `GetConnectedIP` revealed the rest: when `this + 0x8c = 1` (WebSocket mode), the relay IP comes from `HandleAssignRelayIp`, which parses a JSON field in the WebSocket session response containing `relayhost` and `relayport`. The WebSocket connection to wsrelay is used to *negotiate* which relay to connect to, then the actual protobuf auth goes to that relay IP over a *separate* raw TLS connection.

```
App flow (real architecture):
  1. WebSocket JSON login to wsrelay
       → {"result":0, "xmppSupport":true}
       → JSON response: {"relayhost":"<relay_ip>","relayport":"50321",...}
  2. Raw TLS to relayhost:relayport
       → 4-byte-length + protobuf Request(type=6, ...)
       → protobuf Response(result=0, session_token, ...)
  3. Raw TLS to same relay (type=2)
       → protobuf Request(type=2, ipcam_id, ...)
       → MediaPackage video frames
```

The WebSocket is only for JSON login and XMPP message relay. The actual relay auth — both type=6 and type=2 — goes over raw TLS to a relay IP that the camera is already connected to.

I had been sending the protobuf to the wrong endpoint.

---

## Part 4: The Real Problem (And It Wasn't the Endpoint)

Armed with this understanding, I wrote `test_type6_auth.py`: skip the WebSocket entirely, call `getRelayIPList` to find which relay IP the camera is currently connected to, and send the type=6 protobuf there over raw TLS.

Result: still getting connection closed immediately.

Okay. The relay waits patiently if we don't send anything (tested: connect, wait 10 seconds, server stays open). But the moment we send our protobuf, it closes. The encoding must be wrong.

Let me print out exactly what we're sending, field by field:

```
field  1 (string, 24B): "user@example.com"
field  3 (string, 18B): "ANDRC_xxxxxxxxxxxx"
field  4 (string, 18B): "ANDRC_xxxxxxxxxxxx"
field  5 (string, 31B): "{timestamp}_{camera_id}.raw"
field  6 (string, 12B): "ipcamcodec01"
field  7 (varint):       6
field  8 (varint):       1
field  9 (string, 4B):  "13.1"
field 11 (string, 9B):  "websocket"
field 13 (string, 32B): <token>
field 15 (string, 32B): <unified_id>
field 16 (varint):       4
field 20 (string, 12B): "xxxxxxxx-xxx"
field 25 (string, 8B):  "<uid>"
field 27 (varint):       0
```

Field 2 is missing.

Field 2 is the password. It should be an empty string (`""`). The `pb_string` helper function had a guard:

```python
def pb_string(field_num, value):
    if not value:
        return b''   # <-- the bug
    ...
```

An empty string is falsy in Python. So `pb_string(2, "")` returned `b''`. Field 2 was never included in any protobuf we sent. Ever. In any session. Across all the previous attempts.

The relay — which implements proto2-style validation — expected ALL declared fields to be present. When field 2 was missing, it rejected the message by closing the connection. No error message. Just EOF.

Fix: two bytes. `\x12\x00` — the field tag for field 2 (string) followed by zero length.

```python
def pb_string(field_num, value):
    encoded = value.encode('utf-8') if isinstance(value, str) else value
    tag = (field_num << 3) | 2  # wire type 2 = length-delimited
    return encode_varint(tag) + encode_varint(len(encoded)) + encoded
    # Now correctly emits \x12\x00 for empty strings instead of nothing
```

---

## Part 5: It Works

```
[20:35:12] Connecting raw TLS to <relay_ip>:50321...
[20:35:12] TLS connected. Cipher: TLS_CHACHA20_POLY1305_SHA256, Version: TLSv1.3
[20:35:12] Sent type=6 auth (238B)
[20:35:12] Received: 63B

=== PARSING TYPE-6 RESPONSE ===
field 1 (varint): 2           ← message_type = RESPONSE
field 3 (varint): 2           ← ...
Response.result = 0           ← SUCCESS
Response.server_time = "<timestamp>"
Response.cloud_token = "<session_token>"
Response.field7 = 4           ← head_len
Response.field12 = 2

*** RESULT = 0: AUTH ACCEPTED ***
[20:35:17] Server PING → sending PONG
[20:35:22] Server PING → sending PONG
```

The relay accepted the auth. The connection stays alive. The server sends pings every 5 seconds, exactly like a real session.

Type=2 auth to the same relay also worked immediately once the encoding was fixed. Both connections stable, ping/pong running.

---

## Part 6: The Dual-Connection Client

With both auth paths working, I built `relay_remote_client.py` — a client that:

1. Logs into the Closeli API to get a token
2. Queries `getRelayIPList` to find the camera's current relay server
3. Opens a type=6 control connection (raw TLS) and authenticates
4. Opens a type=2 data connection (raw TLS) and authenticates
5. Both connections run ping/pong loops in background threads
6. Saves incoming MediaPackage frames to disk and serves them via HTTP (MJPEG)

```
Client                     Chinese Relay               Camera
  │                              │                        │
  │──── raw TLS type=6 auth ────>│                        │
  │<─── result=0, session ───────│                        │
  │                              │                        │
  │──── raw TLS type=2 auth ────>│                        │
  │<─── result=0 ────────────────│                        │
  │                              │                        │
  │──── LIVE_VIEW (xmpp) ───────>│───── relay ───────────>│
  │                              │<──── MediaPackage ─────│
  │<──── video frames ───────────│                        │
```

The API calls:

```python
# Login
POST https://api.icloseli.com/core/v1/auth/login
Content-Type: application/x-www-form-urlencoded
Params: client_id, device_id, device_name, email, login_type=0, password, sig

# Find camera's relay
POST https://esd.icloseli.com/lookup/v6/getRelayIPList
Params: device_list=[{"device_id":"xxxxS_xxxxxxxxxxxx"}], productKey, sig
→ returns: { "data": { "xxxxS_...": [{"public_ip":"<relay_ip>","download_port":"50321",...}] } }
```

The signing algorithm (MD5V3) was already cracked in the previous session, so this was straightforward.

---

## What's Still Missing

The two relay connections authenticate fine and stay alive. But the camera doesn't start sending video until it receives a LIVE_VIEW XMPP message. That message needs to be routed through the relay to the camera.

Sending `MessageCmd` or `ServerCmd` protobuf messages on the type=6 connection causes the relay to close it immediately — neither format is accepted there. The type=6 connection appears to only handle auth + ping/pong, not XMPP forwarding.

The leading theory is that LIVE_VIEW needs to go through the WebSocket JSON channel (where the real app sends it), not through the raw TLS type=6 connection. That's the next piece to figure out — either by capturing the exact WebSocket message with Frida, or by sniffing it while the real app connects.

Alternatively: just steal the session when the phone app is already streaming. If the phone has already sent LIVE_VIEW and the camera is already sending video to the relay, a type=2 connection with the right auth might start receiving video frames immediately, without needing to send LIVE_VIEW ourselves. Not tested yet.

---

## Lessons Learned

### 1. "WebSocket" was the wrong hypothesis from the start

Every piece of evidence pointed at WebSocket framing as the culprit. But Ghidra showed the code path clearly: `InteractWithServer` → `NonBlockingSSLWrite` → `wolfSSL_write`. Raw bytes into a TLS socket. The WebSocket is only for JSON. Testing the hypothesis against the binary would have saved weeks.

### 2. A silent failure is the most dangerous kind

The relay closed the connection without sending any error. No "400 Bad Request." No "missing field." Just EOF. This made it impossible to distinguish "wrong endpoint," "wrong TLS version," "wrong protobuf encoding," and "wrong auth parameters." Everything looked the same. The fix was to eliminate variables one at a time — and eventually print out the exact bytes being sent.

### 3. Falsy empty strings in Python will ruin your day

`if not value: return b''` is reasonable for most use cases. For a binary protocol that requires every optional field to be explicitly present (proto2 semantics), it's catastrophic. The correct guard is `if value is None`.

### 4. GhidraMCP changes the analysis game

Being able to run 20 Ghidra queries in a conversation — decompile this function, find xrefs to that string, search for functions matching this pattern — without switching windows or waiting for the GUI to catch up, made it possible to trace the full call chain in a single session. The combination of static analysis (Ghidra) and dynamic analysis (Frida) is powerful; adding conversational tooling on top of the static side made it dramatically faster.

---

## Protocol Reference

For completeness, the protobuf fields that the relay actually requires:

**Type=6 (control session)**:
```
user_name(1)=email, password(2)="" (MUST be present!),
device_name(3)=ANDRC_xxx, device_id(4)=ANDRC_xxx,
file_name(5)="{timestamp}_.raw", key(6)="ipcamcodec01",
type(7)=6, use_zlib(8)=1, version(9)="13.1",
channel_name(11)="websocket", cloud_token(13)=api_token,
unified_id(15)=email+timestamp, head_len(16)=4,
product_key(20)="xxxxxxxx-xxx", room_id(25)=uid, channel_no(27)=0
```

**Type=2 (data session)**:
```
user_name(1)=email, password(2)="" (MUST be present!),
device_name(3)=ANDRC_xxx, device_id(4)=ANDRC_xxx,
file_name(5)="{timestamp}_{camera_id}.raw", key(6)="ipcamcodec01",
type(7)=2, use_zlib(8)=1, version(9)="13.1",
channel_name(11)="720p", ipcam_id(12)=camera_device_id,
cloud_token(13)=api_token, unified_id(15)=email+timestamp,
head_len(16)=4, video_width(18)=960, video_height(19)=540,
product_key(20)="xxxxxxxx-xxx", product_secret(21)=secret,
is_manage_event(22)=0, channel_no(27)=0,
flow_info(28)="tId=ANDRC_xxx;nt=1;tt=1;nst=1;ver=13.1;did=ANDRC_xxx"
```

**Auth response** (63 bytes):
```
RelayMessage { message_type=2 (RESPONSE) }
Response { result=0, server_time="<ms timestamp>", session_id=0,
           cloud_token=<echoed back>, field7=4, field12=2 }
```

---

## Code

The code for this project is at [https://github.com/radzki/CloseliStreamServerRemote](https://github.com/radzki/CloseliStreamServerRemote).

---

*This project is conducted for personal use and educational purposes on hardware I own. The goal is local control of my own cameras, not access to anyone else's infrastructure.*
