# Coruna Exploit Toolkit — Payload Decryption Analysis

## Overview

This document describes the full decryption pipeline used to extract the encrypted binary payloads from the Coruna iOS exploit toolkit. Starting from the obfuscated JavaScript files, we reverse-engineered the encryption scheme, recovered the keys from static data in the repository, and successfully decrypted and decompressed all 19 payload bundles — yielding 65+ Mach-O arm64/arm64e dylibs targeting iOS 13–17.

## Exploit Chain Architecture

The exploit chain operates in stages, orchestrated from `group.html`:

1. **Stage 1** — WebKit/WASM memory corruption (builds read/write primitives)
2. **Stage 2** — PAC (Pointer Authentication Code) bypass (for A12+ devices)
3. **Stage 3** — Sandbox escape + payload delivery (`Stage3_VariantB.js`)

Stage 3 builds a Mach-O dylib in-memory (`MachOPayloadBuilder`), loads it into the exploited process, and then feeds encrypted payloads to it via the `window.qbrdr()` bridge function.

## Encryption Pipeline

Payloads go through the following layers (outermost first):

```
[Server] raw encrypted blob
    ↓ (or base64-encoded in JS files for local hosting)
[ChaCha20] DJB variant, 64-bit counter, 64-bit nonce (all zeros)
    ↓
[LZMA/XZ] Apple compression_decode_buffer (algorithm 0x306)
    ↓
[F00DBEEF] Custom container format with multiple Mach-O entries
    ↓
[Mach-O] arm64 / arm64e dylibs
```

### ChaCha20 Details

- **Variant**: Original DJB ChaCha20 (NOT IETF RFC 8439)
  - 64-bit block counter (starting at 0)
  - 64-bit nonce (all zeros)
  - 20 rounds (10 double-rounds)
- **Implementation**: Found at offset `0xad8c` in `bootstrap.dylib`
- **Sigma constant**: Standard `"expand 32-byte k"` at offset `0xbb80`

### LZMA Compression

- Uses Apple's `compression_decode_buffer` with algorithm constant `0x306` (LZMA)
- 8-byte header before compressed data:
  - Bytes 0–3: Magic `0x0BEDF00D` (little-endian)
  - Bytes 4–7: Expected decompressed size (`uint32`)
  - Bytes 8+: XZ/LZMA compressed stream (starts with `fd 37 7a 58 5a 00`)

## Key Recovery

### Master Key (for the manifest file)

The master ChaCha20 key is derived from `fixedMachOVal2`, which is the 3rd argument to `platformModule.init()` in `group.html` line 293:

```javascript
platformModule.init("", fqMaGkNg(), fqMaGkN4([3436285875, 2332907478, 2884495420, 233193687,
                                                1144711575, 1605576699, 1942246444, 1994816675]), ...)
```

The `fqMaGkN4()` function decodes an array of `uint32` values into a 16-character JavaScript string (2 chars per word, using byte-pair encoding). When stored in the Mach-O as UTF-16LE, this yields the 32-byte key:

```
b38fd1ccd6570d8b3ce8edabd740e60d97e93a44fb27b35f2c54c473a37ce676
```

This key decrypts the **manifest file** (`7a7d99099b035b2c6512b6ebeeea6df1ede70fbb`).

### Per-File Keys (for the 18 payload files)

The decrypted manifest (`0xF00DBEEF` magic, 2192 bytes) contains 19 entries, each 100 bytes (0x64):

```
Offset  Size  Field
0x00    6     Header/padding (first entry has flags 0x0013, rest 0x0000)
0x06    2     Flags (iOS version / architecture identifier)
0x08    32    Per-file ChaCha20 key
0x28    48    Filename (40-char hex hash + ".min.js" + NUL + padding)
```

Each payload file has its own unique 32-byte ChaCha20 key. The nonce remains all-zeros.

### Base URL

`fqMaGkNg()` decodes to `./7a7d99099b035b2c6512b6ebeeea6df1ede70fbb.min.js`. After `resolveUrl()` and base extraction, the base URL is `./` (same directory as `group.html`), meaning all payloads are served from `https://sadjd.mijieqi.cn/<hash>.min.js`.

## F00DBEEF Container Format

Each decompressed payload is a custom container:

```
Offset  Size  Field
0x00    4     Magic: 0xF00DBEEF (little-endian, reads as ef be 0d f0)
0x04    4     Entry count (uint32)
0x08    16*N  Entry table (N = entry count)
  +0x00  4    Field 1 (upper 16 bits = segment type)
  +0x04  4    Field 2 (flags, typically 0x00000003)
  +0x08  4    Data offset within file
  +0x0C  4    Data size
[data]        Concatenated entry payloads (Mach-O dylibs, config blobs)
```

### Segment Types

| Type | Description | Typical Size |
|------|-------------|-------------|
| 0x08 | Main implant dylib (targets `powerd`, HTTP C2, crash log paths) | ~196–228 KB |
| 0x09 | Kernel/sandbox escape dylib (entitlements, mount manipulation) | ~230–334 KB |
| 0x0f | Persistence dylib (hooks `launchd`, `powerd`, `AppleCredentialManagerDaemon`) | ~191–192 KB |
| 0x0a | Additional exploit/persistence module (newer iOS variants) | ~50–68 KB |
| 0x05 | Data blob (likely kernel offsets/gadgets) | ~24 KB |
| 0x07 | Small config/metadata blobs | 44 or 468 bytes |

## Manifest Flags & Payload Targeting

The 2-byte flags field (offset 0x06 in each manifest entry) encodes the target iOS version and architecture:

| Flags | Hash | iOS Target | Arch | Entries |
|-------|------|-----------|------|---------|
| 0xf230 | `48000486...` | iOS 15.x | arm64 | 5 (3 dylib) |
| 0xf330 | `b442ab11...` | iOS 15.x | arm64e | 5 (3 dylib) |
| 0xf240 | `5258f6e3...` | iOS 16.0–16.2 | arm64 | 5 (3 dylib) |
| 0xf340 | `a78a9419...` | iOS 16.0–16.2 | arm64e | 5 (3 dylib) |
| 0xf270 | `38af3c8b...` | iOS 16.6–17.0 | arm64 | 5 (3 dylib) |
| 0xf370 | `13344176...` | iOS 16.6–17.0 | arm64e | 7 (4 dylib) |
| 0xf280 | `226cbd84...` | iOS 16.3–16.5 | arm64 | 5 (3 dylib) |
| 0xf380 | `ae7efd66...` | iOS 16.3–16.5 | arm64e | 5 (3 dylib) |
| 0xf290 | `7a1cef00...` | iOS 17.0–17.2 | arm64 | 5 (3 dylib) |
| 0xf390 | `377bed74...` | iOS 17.0–17.2 | arm64e | 7 (4 dylib) |
| 0xf275 | `e9f89858...` | Extended variant | arm64 | 6 (4 dylib) |
| 0xf375 | `f4120dc6...` | Extended variant | arm64e | 6 (4 dylib) |
| 0xf373 | `c8a14d79...` | Extended variant | arm64e | 6 (4 dylib) |
| 0xf383 | `1b2cbbde...` | Extended variant | arm64e | 6 (4 dylib) |
| 0xa205 | `f8a86cf3...` | Older/special | arm64 | 2 (1 dylib) |
| 0xa305 | `72a5ac81...` | Older/special | arm64e | 2 (1 dylib) |
| 0xa306 | `980c77f1...` | Older/special | arm64e | 2 (1 dylib) |
| 0xa303 | `5e89f83e...` | Older/special | arm64 | 3 (2 dylib) |
| 0xa304 | `2a1d692b...` | Older/special | arm64 | 3 (2 dylib) |

## Key Strings Found in Extracted Dylibs

### Implant (type 0x08)
- Targets `powerd` daemon for persistence
- References `/private/var/mobile/Library/Logs/CrashReporter`
- References `/private/var/MobileSoftwareUpdate/Update.plist`
- HTTP/HTTPS C2 communication capability
- Corellium detection: `/usr/libexec/corelliumd`

### Kernel Exploit (type 0x09)
- Mount manipulation: `/private/var/MobileSoftwareUpdate/mnt1`
- Entitlement handling: `com.apple.security.sandbox`, `libCoreEntitlements.dylib`
- Factory mount access: `/private/var/factory_mount`

### Persistence (type 0x0f)
- Hooks into `launchd`, `powerd`, `AppleCredentialManagerDaemon`, `nanoregistrylaunchd`
- Loads system libraries: `libdyld.dylib`, `libSystem.B.dylib`, `libobjc.A.dylib`

## File Layout

```
coruna-main/
├── group.html                      # Main exploit entry point
├── platform_module.js              # Platform detection, key derivation
├── utility_module.js               # Crypto helpers, Int64, LZW
├── Stage3_VariantB.js              # Sandbox escape + MachOPayloadBuilder
├── other/
├── downloaded/                     # 17 files fetched from C2 server
│   └── <hash>.min.js               # Raw encrypted payloads
├── extracted/                      # Base64-decoded qbrdr payloads (from repo JS files)
│   └── <hash>.bin
└── payload/                        # All 19 decrypted + decompressed F00DBEEF containers
    ├── bootstrap.dylib             # Bootstrap dylib to validate and load other dylibs
    ├── 7a7d...payload              # Decrypted manifest (F00DBEEF with 19 download entries)
    ├── <hash>.bin                  # F00DBEEF container
    └── <hash>/                     # Extracted entries per container
        ├── entry0_type0x08.dylib   # Kernel exploit runner -> powerd injector
        ├── entry1_type0x09.dylib   # Kernel exploit <- what jailbreak developers are most interested in
        ├── entry2_type0x0f.dylib   # powerd implant, repurposed for SpringBoard
        ├── entry3_type0x07.bin
        └── ...
```

## Reproduction Steps

1. **Decode master key** from `fqMaGkN4([3436285875, ...])` in `group.html:293` → UTF-16LE → 32 bytes
2. **Decrypt manifest** (`7a7d...`): ChaCha20(master_key, nonce=0) → check `0x0BEDF00D` → LZMA decompress
3. **Parse manifest**: 19 entries at offset 0x120, each 0x64 bytes; per-file key at entry+8 (32 bytes)
4. **Download missing payloads** from `https://sadjd.mijieqi.cn/<hash>.min.js` (raw binary)
5. **Decrypt each payload**: ChaCha20(per_file_key, nonce=0) → check `0x0BEDF00D` → LZMA decompress
6. **Parse F00DBEEF containers**: extract Mach-O dylibs by entry table offsets
