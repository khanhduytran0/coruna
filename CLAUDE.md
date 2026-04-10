# CLAUDE.md

## Project Overview

Coruna is a leaked and partially deobfuscated iOS exploit toolkit targeting iOS 15.x through 17.x. It implements multi-stage WebKit-based exploit chains that achieve memory corruption, PAC bypass, sandbox escape, and native payload delivery. Originally extracted from `https://sadjd.mijieqi[.]cn/group.html`.

This repository contains the symbolicated/deobfuscated source alongside pre-compiled dylibs, decrypted payloads, and a TweakLoader for post-exploitation.

## Repository Structure

```
coruna/
├── group.html                    # Main entry point — web UI orchestrating all exploit stages
├── platform_module.js            # Platform detection, iOS version checks, feature flags
├── utility_module.js             # Type conversion, Int64 arithmetic, crypto, LZMA decompression
│
├── Stage1_*.js                   # Stage 1: WebKit memory corruption (3 variants)
│   ├── Stage1_15.2_15.5_jacurutu.js      # iOS 15.2–15.5 (arm64)
│   ├── Stage1_16.2_16.5.1_terrorbird.js  # iOS 16.2–16.5.1 (arm64e)
│   ├── Stage1_16.6_17.2.1_cassowary.js   # iOS 16.6–17.2.1 (arm64/arm64e)
│   ├── Stage1_18.0_18.x_manticore.js     # iOS 18.0–18.x (stub)
│   └── Stage1_26.0_26.x_chimera.js       # iOS 26.0–26.x (stub)
│
├── Stage2_*.js                   # Stage 2: PAC bypass (seedbell + new variants)
│   ├── Stage2_16.3_16.5.1_seedbell.js
│   ├── Stage2_16.6_16.7.12_seedbell.js
│   ├── Stage2_16.6_17.2.1_seedbell_pre.js
│   ├── Stage2_17.0_17.2.1_seedbell.js
│   ├── Stage2_18.0_18.x_thornvine.js     # iOS 18.x PAC bypass (stub)
│   └── Stage2_26.0_26.x_ironroot.js      # iOS 26.x PAC bypass (stub)
│
├── Stage3_VariantB.js            # Stage 3: Sandbox escape, Mach-O builder, payload delivery
├── Atria.dylib                   # Pre-compiled arm64/arm64e exploit helper dylib
│
├── TweakLoader/                  # Native iOS tweak loader (Objective-C / C)
│   ├── Makefile                  # Theos build config
│   ├── TweakLoader.m             # Main loader — PAC-aware, dyld bypass init
│   ├── lv_bypass.c               # dyld library validation bypass
│   ├── control                   # Cydia package metadata
│   ├── CydiaSubstrate_arm64e     # Substrate library for arm64e
│   ├── Atria_arm64e              # Atria dylib for arm64e
│   └── SpringBoardTweak/         # Post-exploit SpringBoard hook
│       ├── Makefile
│       ├── SpringBoardTweak.h
│       └── SpringBoardTweak.m
│
├── CydiaSubstrate.framework/     # Cydia Substrate runtime (hooking framework)
│
├── payloads/                     # Decrypted F00DBEEF payload containers
│   ├── manifest.json             # 19 payload entries with metadata (type, size, hash)
│   ├── bootstrap.dylib           # Bootstrap loader (arm64)
│   ├── TweakLoader.dylib         # Compiled tweak loader
│   └── <hash>/                   # Per-target extracted containers with typed entries
│       ├── entry0_type0x08.dylib # Kernel exploit runner
│       ├── entry1_type0x09.dylib # Kernel/sandbox escape
│       ├── entry2_type0x0f.dylib # Persistence (powerd/SpringBoard hook)
│       ├── entry3_type0x07.bin   # Config metadata
│       ├── entry4_type0x05.bin   # Kernel offsets/gadgets
│       └── entry5_type0x09.dylib # Alternative kernel exploit
│
├── downloaded/                   # Raw encrypted payloads from C2 server (.min.js)
├── extracted/                    # Base64-decoded intermediate payload blobs
├── other/                        # Miscellaneous files and notes
├── ANALYSIS.md                   # Technical breakdown of decryption and payload format
└── README.md                     # Project overview and tested device table
```

## Exploit Chain Architecture

The toolkit operates in three stages:

1. **Stage 1 — WebKit Memory Corruption**: Targets JavaScriptCore heap to build `read32`/`write64` primitives. Three variants cover different iOS version ranges and CPU architectures (arm64 vs arm64e).

2. **Stage 2 — PAC Bypass**: Circumvents Pointer Authentication Code on arm64e devices. Multiple seedbell variants target different iOS version ranges.

3. **Stage 3 — Sandbox Escape & Payload Delivery**: `Stage3_VariantB.js` parses Mach-O binaries, resolves exports, escapes the sandbox, and delivers native dylib payloads to paths under `/private/var/MobileSoftwareUpdate/`.

### Payload Encryption Pipeline

```
Raw payload → ChaCha20-DJB (nonce=0, 20 rounds) → LZMA (algo 0x306) → F00DBEEF container → Mach-O dylibs
```

- **Magic**: `0xF00DBEEF` container format
- **Master key**: Derived from `fqMaGkN4()` in `group.html` → UTF-16LE → 32 bytes
- **Per-file keys**: Stored in manifest entries (offset +8)

## Languages & Technologies

| Language | Purpose | Key Files |
|----------|---------|-----------|
| JavaScript | Exploit chain orchestration | `group.html`, `*.js` |
| Objective-C | iOS dylib tweaking & hooking | `TweakLoader.m`, `SpringBoardTweak.m` |
| C | Low-level dyld bypass | `lv_bypass.c` |
| Mach-O binaries | Pre-compiled arm64/arm64e dylibs | `*.dylib` |

## Build System

**Framework**: [Theos](https://theos.dev/) (iOS jailbreak development framework)

### Build Commands

Build TweakLoader:
```bash
cd TweakLoader && make TARGET=iphone:clang:latest:15.0 ARCHS="arm64 arm64e"
```

Build SpringBoardTweak:
```bash
cd TweakLoader/SpringBoardTweak && make
```

### Build Configuration

- `FINALPACKAGE=1` — Release build
- `STRIP=0` — Keep symbols for debugging
- `GO_EASY_ON_ME=1` — Relaxed compiler warnings
- Install path: `/usr/local/lib`
- TweakLoader embeds SpringBoardTweak via `-sectcreate __TEXT __SBTweak`

### Prerequisites

- Theos framework installed and `$THEOS` set
- iOS SDK / cross-compilation toolchain
- No package manager (dependencies are vendored/pre-compiled)

## Key Conventions

- **File naming**: Stage files follow the pattern `Stage{N}_{iOS_range}_{codename}.js`
- **Module system**: `globalThis.moduleManager` with hex-hash module IDs
- **Deobfuscation comments**: Deobfuscated names annotated as `// Original: X → descriptiveName`
- **Payload types**: Numeric type IDs (`0x05` offsets, `0x07` metadata, `0x08` kernel exploit, `0x09` sandbox escape, `0x0f` persistence)
- **Architecture awareness**: Code branches on arm64 vs arm64e; PAC handled via `__builtin_ptrauth_*`
- **Error codes**: Negative hex sentinel values (e.g., `-0x41414141`) for diagnostics
- **Device targeting**: iOS version + CPU type encoded in manifest flags (`0xf230`, `0xf240`, etc.)

## Tested Devices

| Device | iOS Version | Exploit Chain | Status |
|--------|-------------|---------------|--------|
| iPhone 6s+ | 15.4.1 | jacurutu → VariantB | Tested |
| iPhone Xs Max | 16.5 | terrorbird → seedbell → VariantB | Tested |
| iPhone 15 Pro Max | 17.0 | cassowary → seedbell_pre → seedbell_17 → VariantB | Tested |
| (TBD) | 18.1 | manticore → thornvine → VariantB | Stub |
| (TBD) | 26.1 | chimera → ironroot → VariantB | Stub |

## Dependencies

All dependencies are vendored — no package manager is used.

| Dependency | Notes |
|------------|-------|
| Cydia Substrate | Included as framework + arm64e binary |
| Atria dylib | Pre-compiled, committed to repo |
| Theos | External requirement (build framework) |
| System libs | `libSystem.B`, `libobjc.A`, `libdyld` (linked at runtime on device) |

## No CI/CD

There is no CI/CD pipeline. Builds are run manually via Theos Makefiles. There are no automated tests or linting configurations.

## Git Conventions

- Commit messages are short and descriptive (no conventional commits format)
- `.gitignore` excludes: `.DS_Store`, `*.o`, `.theos/`, IDA analysis files (`*.i64`, `*.id0`, `*.id1`, `*.nam`, `*.til`)
- Pre-compiled binaries and decrypted payloads are committed to the repository

## Additional Documentation

- [`ANALYSIS.md`](ANALYSIS.md) — Detailed technical analysis of decryption process and iOS payload version table
- [`other/README.md`](other/README.md) — Notes on dumped dylibs and obfuscated sources
