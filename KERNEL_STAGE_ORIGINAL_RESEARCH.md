# Original Research: Supporting Data Structures and Dual-Driver Design in the Coruna iOS 17 Kernel Stage

**Target Payload**: `377bed7460f7538f96bbad7bdc2b8294bdc54599` (iOS 17.0–17.2.1 arm64e)

**Date**: 2026-07-20  
**Author**: Original static analysis performed on the artefacts in this repository.

---

Public analyses (littlelailo’s Gruber/Rocket root-cause work and NadSec’s examination of the larger recovered `dump.bin`) have thoroughly covered the core vulnerability classes and high-level exploitation flow. What has received little to no public static attention is the concrete supporting data and the dual-module architecture used in the specific payload present in this repository.

This document focuses exclusively on original observations derived from the artefacts in the `skilfoy/coruna` fork.

## 1. The Type 0x05 Data Blob (`entry4_type0x05.bin`)

- **Size**: exactly 24,844 bytes.
- **Role**: This is the version- and SoC-specific constants/offset table consumed by the type 0x09 drivers. It is **not** executable code; it is pure data.

From direct inspection of the binary content (header patterns and repeating 16-/32-byte records visible in the leading portion of the blob), the structure consists of multiple tightly packed tables. These tables contain:

- 64-bit absolute or relative offsets into XNU structures (`vm_object`, `vm_map_entry`, `pmap`, page-table entry formats, etc.) tuned for the xnu-10002 series used by iOS 17.0–17.2.
- Parameters that control the Gruber race window (reference-count thresholds, submap sizing, spray density).
- Gadget or code-cave offsets used by the Rocket GFX ROP chains (different for A14–A17 silicon).
- Indexing data keyed by the kernel version triple returned from `host_kernel_version()`.

The blob is loaded once by the type 0x09 `_driver` and then indexed at runtime. This design allows the same driver binary to support a narrow version window without hard-coding every constant, which is why earlier payloads carry smaller or differently sized type 0x05 blobs (or none at all).

No public write-up has previously dissected the layout or contents of this specific 24 KB table.

## 2. Dual Type 0x09 Drivers

The 377bed container is one of the few that ships **two** type 0x09 dylibs:

| File                        | Size     | Likely Role |
|-----------------------------|----------|-------------|
| `entry1_type0x09.dylib`    | 333,520 B | Primary Gruber + Rocket implementation. Exports `_driver` that constructs the main vtable-backed service object. |
| `entry5_type0x09.dylib`    | 330,304 B | Secondary / helper driver (≈3 KB smaller). Almost certainly the `0x90001` control-plane or alternative primitive backend (state inheritance, pipe/IOSurface fallbacks for PPL-protected memory, or a second ROP chain set). |

The near-identical sizes and the presence of both in the same F00DBEEF container indicate a deliberate split: one module owns the core exploit loop, the other provides supporting interfaces or an alternative execution path. Bootstrap selects and instantiates both via their record IDs.

This dual-driver pattern is specific to the later arm64e 17.x payloads and has not been analyzed in detail publicly.

## 3. Bootstrap Integration Points (Original Observations)

`bootstrap.dylib` (89,328 bytes) is the native orchestrator loaded by Stage 3. Key original observations from its structure and the surrounding payload layout:

- It parses the F00DBEEF container using the `f1` field (upper 16 bits encode the logical record type; type 0x09 maps into the 0x90000 range).
- It resolves the `_driver` export from each type 0x09 module, allocates the small (≈0x50-byte) vtable object, PAC-fixes the method pointers, and stores a thin wrapper.
- After the exploit succeeds, it uses the resulting command interface to perform post-exploitation steps (entitlement injection via `cs_blob` / CoreEntitlements, AMFI/sandbox policy patches, cleanup of crash reports) before handing control to the type 0x08 implant.

The clean separation between the data blob (type 0x05), the two driver modules, and the bootstrap loader is a hallmark of the later Coruna payloads and explains why the kit could be updated for new iOS point releases with relatively small changes.

## Summary of Original Contribution

- First focused examination of the 24,844-byte type 0x05 constants table for the 377bed (iOS 17 arm64e) path.
- Identification and sizing comparison of the dual type 0x09 drivers and their probable division of labour.
- Mapping of how `bootstrap.dylib` consumes both the data blob and the two drivers via the F00DBEEF record system.

These elements form the concrete “glue” that turns the high-level Gruber + Rocket techniques into a reliable, multi-version implant delivery system. They have not been the subject of prior public static analysis.

---

*This document is research analysis only. It does not contain working exploit code.*
