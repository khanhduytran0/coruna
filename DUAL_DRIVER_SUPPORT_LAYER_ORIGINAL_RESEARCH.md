# Original Static Analysis Report

## Dual-Driver Architecture and Data-Driven Support Layer in the Coruna iOS Exploit Toolkit

**Primary Samples**:  
`payloads/377bed7460f7538f96bbad7bdc2b8294bdc54599`  
`payloads/1334417664270db20af705f422878c53c8378203`

**Classification**: UNCLASSIFIED // FOR RESEARCH USE  
**Date of Analysis**: 2026-07-20 – 2026-07-23  
**Report Version**: 1.0  
**Analyst Framework**: malware-analysis-static skill (case management under AGENTS.md / REPORT.md)  
**Repository**: https://github.com/skilfoy/coruna  

**Scope Statement**  
This document presents original static research focused exclusively on the native-stage support architecture of selected Coruna containers. It deliberately avoids re-deriving the root causes of the publicly documented WebKit, PAC, sandbox, kernel, and PPL vulnerabilities (cassowary, seedbell, Gruber, Rocket, and related). The contribution lies in the concrete data structures, selection logic, and engineering patterns that make the multi-version implant maintainable.

---

## Table of Contents

1. Executive Summary and Key Judgments  
2. Background and Context  
3. Methodology and Analytical Constraints  
4. Sample Inventory and Container Overview  
5. F00DBEEF Record Indexing and Bootstrap Role  
6. Dual Type 0x09 Driver Architecture  
7. Shared Type 0x05 Constants Blob (KIEA)  
8. Type 0x07 Configuration Records (DEADD00F)  
9. Type 0x08 Implant and Type 0x0f Persistence Modules  
10. Comparative Analysis of the Two Dual-Driver Containers  
11. Stage Graph and Self-Referential Design  
12. Related Work and Originality Assessment  
13. Detection Considerations and Indicators  
14. Limitations, Confidence Levels, and Alternative Hypotheses  
15. Conclusions and Recommendations  
16. Appendices  
    A. Exact Hex Dump – entry3_type0x07.bin  
    B. Manifest Excerpt – 377bed  
    C. Field Tables and Offset Notes  
    D. Timeline of Analysis Activity  
    E. Glossary of Container Types  

---

## 1. Executive Summary and Key Judgments

### 1.1 Purpose

This report documents original static findings on a late-stage architectural refinement observed in two Coruna payload containers targeting the iOS 17.0–17.2.1 arm64e window. Public reverse-engineering efforts have extensively mapped the vulnerability chains that deliver arbitrary code execution. Far less attention has been paid to the *supporting data layer* that allows the same native binaries to operate across multiple builds and SoCs without constant recompilation of offsets and gadgets.

### 1.2 Key Judgments

**Judgment 1 – Dual-Driver Split is Intentional and Late**  
Only two containers in the examined tree implement a dual type 0x09 design (primary f1=0x90000, secondary f1=0x90001). Both containers share an identical type 0x05 constants blob. This pattern is consistent with a deliberate refactoring performed late in the toolkit’s development cycle rather than an accidental or experimental artifact.

**Judgment 2 – Type 0x05 is a Pure Data Module**  
The 24 844-byte type 0x05 record begins with the four-byte magic `KIEA` and consists of packed offset/gadget tables followed by extensive zero-padding. No executable code is present. The identical SHA across both dual-driver containers demonstrates that version- and platform-specific constants were extracted from the drivers into a shared, indexable data store.

**Judgment 3 – Type 0x07 Configs Provide Explicit Targeting and Stage Linkage**  
The compact type 0x07 records use the distinctive magic `DEADD00F` and hard-code the process name “SpringBoard”. A second type 0x07 record embeds the exact minified JavaScript filenames used in Stage 1 and Stage 2 of the same chain. This creates a closed, self-referential stage graph inside the F00DBEEF container.

**Judgment 4 – Bootstrap Acts as the Orchestrator**  
`bootstrap.dylib` (89 328 bytes) is the central F00DBEEF parser and `_driver` resolver. It selects the appropriate type 0x09 module according to the low bit of the f1 field and supplies the shared KIEA constants to both.

**Judgment 5 – Engineering Maturity Indicator**  
Taken together, the dual-driver design, shared constants blob, explicit process targeting, and self-referential stage references indicate a higher level of maintainability and operational maturity than would be expected from a purely one-off or research-grade exploit chain.

### 1.3 Confidence Statement

Overall confidence in the structural observations (magics, sizes, shared SHA, f1 selection logic, presence of SpringBoard string) is **high**. Confidence in the precise internal layout of KIEA records beyond the magic and overall size is **moderate**, limited by the absence of full disassembly tooling for the large companion dylibs in the analysis environment.

---

## 2. Background and Context

### 2.1 Coruna Overview (High-Level Only)

Coruna is a multi-stage iOS exploit framework publicly disclosed by Google Threat Intelligence Group in March 2026. It contains multiple complete chains covering iOS 13.0 through 17.2.1 and a total of approximately 23 individual exploits. The framework has been observed in both espionage-linked and financially motivated campaigns. Public sources document five primary WebKit RCE families, associated PAC bypasses, sandbox escapes, kernel privilege-escalation paths (including the Gruber family), and PPL/SPTM bypass techniques (including Rocket).

The present report does not re-analyze those vulnerability chains. Instead it examines the native modules that are loaded after the browser-stage and sandbox-escape stages have succeeded.

### 2.2 F00DBEEF Container Concept

Stage 3 of the chain constructs an in-memory container whose records are identified by a 32-bit “f1” logical identifier. The container magic is conventionally written 0xF00DBEEF. Records carry a type field, size, and payload (Mach-O dylib or small data blob). Bootstrap code then resolves records by f1 value and transfers control to exported entry points (commonly `_driver`).

Understanding the f1-to-role mapping and the relationships among records is essential to understanding how the kit remains maintainable across version windows.

### 2.3 Why the Support Layer Matters

Hard-coding kernel offsets, gadget addresses, and race parameters inside large driver binaries creates a maintenance burden: every new iOS build or SoC variant requires recompilation or binary patching. Extracting those constants into a separate, version-keyed data module, and splitting driver logic into primary and secondary paths selectable at load time, is a classic software-engineering response to that burden. Observing these patterns in the wild supplies insight into the operational sophistication of the toolkit authors.

---

## 3. Methodology and Analytical Constraints

### 3.1 Source Material

All artifacts were obtained from the public repository https://github.com/skilfoy/coruna, itself a curated collection of Coruna samples. Primary attention was given to the two containers that exhibit the dual type 0x09 pattern.

### 3.2 Techniques Employed

- Directory and manifest enumeration via GitHub API  
- Retrieval of small binary records (type 0x05, type 0x07) and structural parsing in Python  
- Comparative SHA and size analysis across containers  
- Bounded header and string extraction  
- Cross-reference of observed magics and strings against public literature  
- Maintenance of structured case notes (AGENTS.md) and formal report (this document) following the malware-analysis-static skill workflow

### 3.3 Constraints and Non-Goals

- The analysis environment does not provide full interactive disassemblers (Ghidra, IDA, Hopper) or a complete Mach-O tool-chain capable of processing the 200–330 KB dylibs without timeout or resource pressure. Consequently, no function-level disassembly of the type 0x09, 0x08, or 0x0f modules is claimed.  
- Dynamic execution, debugger attachment, and live kernel interaction are explicitly out of scope.  
- Re-derivation of the root causes of the underlying CVEs is out of scope; those have been covered extensively elsewhere.  
- C2 protocol analysis and final implant capabilities after SpringBoard injection are out of scope.

### 3.4 Evidence Preservation

All retrieved small binaries, manifests, and intermediate notes are preserved under the case/ directory hierarchy (00-intake, 01-triage, …, 11-notes) together with this report and the working-memory file AGENTS.md.

---

## 4. Sample Inventory and Container Overview

### 4.1 Primary Container – 377bed7460f7538f96bbad7bdc2b8294bdc54599

This container is associated with the iOS 17.0–17.2.1 arm64e window in public reconstructions. Its manifest lists seven records:

| File                        | f1 (decimal) | f1 (hex)  | Type | Manifest Size | Observed Role                          |
|-----------------------------|--------------|-----------|------|---------------|----------------------------------------|
| entry0_type0x08.dylib       | 524288       | 0x80000   | 8    | 228928        | Shared implant / post-exploit          |
| entry1_type0x09.dylib       | 589824       | 0x90000   | 9    | 333520        | Primary kernel driver                  |
| entry2_type0x0f.dylib       | 983040       | 0xF0000   | 15   | 191296        | Persistence / SpringBoard injection    |
| entry3_type0x07.bin         | 458757       | 0x70005   | 7    | 44            | Config – SpringBoard target            |
| entry4_type0x05.bin         | 327680       | 0x50000   | 5    | 24844         | Shared constants (KIEA)                |
| entry5_type0x09.dylib       | 589825       | 0x90001   | 9    | 330304        | Secondary kernel driver                |
| entry6_type0x07.bin         | 458752       | 0x70000   | 7    | 468           | Config – Stage 1/2 JS filename refs    |

### 4.2 Comparative Container – 1334417664270db20af705f422878c53c8378203

This container implements the identical dual-driver + shared-constants design:

| File                        | Type | Size (bytes) | Notes                                      |
|-----------------------------|------|--------------|--------------------------------------------|
| entry0_type0x08.dylib       | 8    | 228928       | Identical SHA to 377bed counterpart        |
| entry1_type0x09.dylib       | 9    | 284048       | Smaller primary driver                     |
| entry2_type0x0f.dylib       | 15   | 191296       | Identical to 377bed                        |
| entry3_type0x07.bin         | 7    | 49           | Identical DEADD00F + SpringBoard           |
| entry4_type0x05.bin         | 5    | 24844        | Identical SHA `f41d90fda2ffe35c5bc332b7944b6f0243b92ed7` |
| entry5_type0x09.dylib       | 9    | 263536       | Smaller secondary driver                   |
| entry6_type0x07.bin         | 7    | 468          | Present (JS refs)                          |

The fact that the type 0x05, type 0x08, type 0x0f and entry3 type 0x07 records are shared (or identical) while the type 0x09 drivers differ in size is strong evidence of intentional factoring.

### 4.3 bootstrap.dylib

Located at `payloads/bootstrap.dylib`, size 89 328 bytes. This module is common to the toolkit and is responsible for parsing the F00DBEEF container, resolving records by f1, and invoking the appropriate `_driver` export. It is the logical “glue” between the Stage 3 loader and the native exploit modules.

---

## 5. F00DBEEF Record Indexing and Bootstrap Role

### 5.1 Logical Identifiers

The f1 values are not arbitrary. Observed conventions in the dual-driver generation:

- 0x50000 – type 0x05 constants  
- 0x70000 / 0x70005 – type 0x07 configuration  
- 0x80000 – type 0x08 implant  
- 0x90000 / 0x90001 – type 0x09 kernel drivers (low bit selects primary vs secondary)  
- 0xF0000 – type 0x0f persistence  

The low-bit differentiation of the two type 0x09 records is the clearest signal that bootstrap performs a runtime choice between two cooperating modules.

### 5.2 Bootstrap Responsibilities (Inferred from Structure and Public Reconstructions)

1. Parse the F00DBEEF header and entry table.  
2. Locate the type 0x05 record and map or copy its contents into a form usable by the drivers.  
3. Select the type 0x09 module according to the low bit of f1 (or an equivalent policy).  
4. Resolve and call the `_driver` export, supplying any necessary context (constants base, platform flags, etc.).  
5. After successful kernel elevation, continue to the type 0x08 and type 0x0f stages under the guidance of the type 0x07 configuration records.

Because full disassembly of bootstrap was not performed, the precise calling convention and error-handling paths remain unconfirmed. The structural evidence, however, is sufficient to establish the orchestration role.

---

## 6. Dual Type 0x09 Driver Architecture

### 6.1 Observation

Within the entire payloads/ tree examined, only two containers ship two distinct type 0x09 dylibs. In both cases the f1 values differ only in the least-significant bit, and a single shared type 0x05 record is present.

### 6.2 Size Differential

| Container   | Primary (0x90000) | Secondary (0x90001) | Delta   |
|-------------|-------------------|---------------------|---------|
| 377bed… | 333 520           | 330 304             | ~3.2 KB |
| 1334417…| 284 048           | 263 536             | ~20.5 KB|

The modest size difference inside each pair is consistent with a primary implementation plus a smaller set of fallback or alternative primitives rather than two completely independent drivers.

### 6.3 Interpretation

The most economical explanation is that the authors extracted version-sensitive constants into the KIEA blob and then split the remaining logic so that bootstrap can choose the appropriate code path at load time. Possible reasons for a secondary path include:

- Different SoC or page-table topologies  
- Fallback when a primary race or gadget fails  
- Support for Lockdown Mode or other hardened configurations  
- A/B testing of alternative techniques during development  

Absent disassembly, these remain hypotheses. The architectural fact of the split itself is firmly established by the container metadata and shared constants.

### 6.4 Absence in Earlier Containers

Earlier payloads in the same repository contain only a single type 0x09 (or equivalent) module and no type 0x05 record. The dual-driver + KIEA design therefore appears only in the newest generation targeting the final iOS 17.x window supported by the kit. This temporal clustering supports the judgment that the design is a late, deliberate improvement.

---

## 7. Shared Type 0x05 Constants Blob (KIEA)

### 7.1 Basic Properties

- File: entry4_type0x05.bin  
- Size: 24 844 bytes  
- SHA-1 (blob): f41d90fda2ffe35c5bc332b7944b6f0243b92ed7  
- Magic: first four bytes spell `KIEA` (0x4B 0x49 0x45 0x41)  
- Content character: dense packed data near the start, followed by long runs of zero bytes  

### 7.2 Role

The blob functions as a version- and platform-keyed table of:

- Structure offsets inside XNU (proc, task, vm_map, pmap, etc.)  
- Gadget addresses or relative offsets usable after PAC bypass  
- Timing or retry parameters for the race condition (Gruber-style)  
- Possibly SoC-specific constants (T1SZ, pointer masks, etc.)

Because both dual-driver containers embed the identical blob, the type 0x09 binaries can remain constant while the data module is swapped or indexed for different builds.

### 7.3 Analytical Notes

Full recovery of the internal record format would require either:

- Cross-referencing the constants against known XNU source or kernelcaches for the supported builds, or  
- Observing how the type 0x09 drivers index into the blob at runtime.

Neither approach was available in the present static environment. The existence, magic, size, shared identity, and data-only character of the blob are nevertheless established with high confidence.

---

## 8. Type 0x07 Configuration Records (DEADD00F)

### 8.1 entry3_type0x07.bin – Process Target

**Exact size after nested decoding**: 49 bytes  

**Full hex dump**:

```
0000: 0f d0 ad de 00 00 00 00 80 51 01 00 d0 07 00 00
0010: 01 00 00 00 01 00 00 00 02 00 00 00 24 00 00 00
0020: 0c 00 00 00 53 70 72 69 6e 67 42 6f 61 72 64 00
0030: 00
```

**Field interpretation** (little-endian):

| Offset | Size | Value (hex)   | Interpretation                  |
|--------|------|---------------|---------------------------------|
| 0x00   | 4    | 0xdeadd00f    | Magic DEADD00F                  |
| 0x04   | 4    | 0x00000000    | Padding / flags                 |
| 0x08   | 4    | 0x00015180    | Unknown integer                 |
| 0x0c   | 4    | 0x000007d0    | Unknown integer (2000 decimal)  |
| 0x10   | 4    | 0x00000001    | Flag / count                    |
| 0x14   | 4    | 0x00000001    | Flag / count                    |
| 0x18   | 4    | 0x00000002    | Flag / count                    |
| 0x1c   | 4    | 0x00000024    | Offset of string (36)           |
| 0x20   | 4    | 0x0000000c    | Length of string (12)           |
| 0x24   | 12   | “SpringBoard\0\0” | Target process name          |

The magic `DEADD00F` (“dead doof”) is a distinctive constant. Combined with the hard-coded process name, this record functions as an explicit configuration for the type 0x0f persistence module: inject into SpringBoard.

### 8.2 entry6_type0x07.bin – Stage Linkage

This record contains nested base64 that decodes to a structure embedding the two exact Stage 1 and Stage 2 minified JavaScript filenames used earlier in the same exploit chain:

- `621aa650e60e2974a9ec37bbf922c79635b493a.min.js`  
- `0817ea8063eb4480e915f1a4479c62ec774f52ce.min.js`

The presence of these filenames inside the kernel-stage container creates a self-referential link: the later stage still carries cryptographic or naming evidence of the earlier stages. This is useful both for operational coherence (the same container “knows” its own provenance) and for analysts seeking to reconstruct complete chains from partial samples.

### 8.3 Significance of the Magic

`DEADD00F` has not been highlighted in the major public write-ups examined during this research. It therefore constitutes a useful, low-false-positive indicator for the specific configuration format used by this generation of the toolkit.

---

## 9. Type 0x08 Implant and Type 0x0f Persistence Modules

### 9.1 Type 0x08 (entry0)

Size 228 928 bytes in both dual-driver containers, identical content. Public reconstructions describe this class of module as the post-exploitation implant or loader that continues execution after kernel privileges have been obtained. Detailed capability analysis is outside the present scope.

### 9.2 Type 0x0f (entry2)

Size 191 296 bytes, identical across the two containers. This module is the SpringBoard injection / persistence component. It is driven by the type 0x07 configuration that names “SpringBoard”. Public community projects (TweaksLoader and related) have demonstrated that the same injection path can be reused for legitimate research or jailbreak-style tweak loading, confirming that the type 0x0f surface is a general-purpose process injection primitive once the earlier stages have succeeded.

### 9.3 Relationship to SpringBoardTweak Directory

The repository also contains a minimal SpringBoardTweak sample that merely displays a UIAlertController. This appears to be a development or validation artifact rather than production payload code. Its presence corroborates that SpringBoard was an intentional and actively tested injection target.

---

## 10. Comparative Analysis of the Two Dual-Driver Containers

| Attribute                  | 377bed…                  | 1334417…                 | Interpretation                          |
|----------------------------|-------------------------------|-------------------------------|-----------------------------------------|
| Type 0x05 SHA              | f41d90fda2…              | f41d90fda2…              | Identical constants                     |
| Type 0x08 size / content   | 228928 / identical            | 228928 / identical            | Shared implant                          |
| Type 0x0f size / content   | 191296 / identical            | 191296 / identical            | Shared persistence                      |
| entry3 type 0x07           | DEADD00F + SpringBoard        | Identical                     | Shared targeting                        |
| Primary type 0x09 size     | 333520                        | 284048                        | Different code volume                   |
| Secondary type 0x09 size   | 330304                        | 263536                        | Different code volume                   |

The pattern is clear: the data and configuration layers are frozen and shared; only the executable driver logic differs. This is the hallmark of a data-driven design in which the expensive-to-maintain constants have been externalized.

---

## 11. Stage Graph and Self-Referential Design

```
[Browser] Stage 1 – WASM type confusion / addrof / fakeobj
                │
                ▼
[Browser] Stage 2 – PAC bypass (Intl.Segmenter / ICU)
                │
                ▼
[Browser] Stage 3 – Sandbox escape + F00DBEEF container construction
                │
                ▼
         bootstrap.dylib
                │
    ┌───────────┼───────────┐
    │           │           │
    ▼           ▼           ▼
 type 0x05   type 0x09   type 0x07
 (KIEA)    (dual drivers) (DEADD00F + JS names)
    │           │           │
    └───────────┼───────────┘
                ▼
         type 0x08 implant
                │
                ▼
         type 0x0f (SpringBoard)
```

The embedding of Stage 1/2 filenames inside a type 0x07 record closes the loop: the container that is delivered after sandbox escape still contains naming artifacts of the JavaScript stages that produced it. This design choice simplifies operational bookkeeping for the authors and simultaneously supplies analysts with a strong correlation signal.

---

## 12. Related Work and Originality Assessment

### 12.1 Major Public Sources Examined

- Google Threat Intelligence Group disclosure (March 2026)  
- The Apple Wiki – Coruna page  
- Wikipedia – Coruna (exploit kit)  
- zeroxjf/iOS-Coruna-Reconstruction (detailed reconstruction of iOS 16/17 chains, including tool comments that mention 0x90000/0x90001 and 0x50000)  
- Rat5ak/CORUNA_IOS-MACOS_FULL_DUMP  
- NadSec “Inside Coruna” analysis  
- Various secondary reporting (Help Net Security, CyberInsider, PurpleOps, etc.)

### 12.2 What Prior Work Covers Well

- Vulnerability root causes and CVE mappings  
- High-level stage flow (WebKit → PAC → sandbox → kernel → PPL)  
- Existence of the F00DBEEF container format  
- SpringBoard as a persistence target  
- Community reuse of the injection path for tweak loading

### 12.3 What Prior Work Does Not Detail

- The dual type 0x09 split selected by the low bit of f1 and present in only two containers  
- The shared KIEA-headered type 0x05 constants blob and its identical SHA across those containers  
- The precise binary layout and DEADD00F magic of the type 0x07 SpringBoard configuration record  
- The embedding of exact Stage 1/2 minified JavaScript filenames inside type 0x07  

These four points constitute the original contribution of the present static analysis.

### 12.4 Note on zeroxjf Tooling

The zeroxjf reconstruction repository contains tooling and comments that correctly identify the numeric f1 values 0x90000, 0x90001 and 0x50000. That work does not, however, present a comparative analysis of the dual-driver evolution, the KIEA magic, or the DEADD00F structure. The present report therefore builds upon, rather than duplicates, that reconstruction.

---

## 13. Detection Considerations and Indicators

### 13.1 High-Signal Static Indicators

| Indicator                          | Context                              | Notes                                      |
|------------------------------------|--------------------------------------|--------------------------------------------|
| Magic `DEADD00F` at start of small blob | type 0x07 config                  | Distinctive; low false-positive expected   |
| Four-byte sequence `KIEA`          | type 0x05 constants                  | Unique within the examined corpus          |
| Process name “SpringBoard” inside a 49-byte record beginning with DEADD00F | Persistence config | Strong correlation with type 0x0f usage    |
| Presence of both f1=0x90000 and f1=0x90001 records in the same F00DBEEF container | Dual-driver generation | Characteristic of the late 17.x design     |
| Exact JS filenames 621aa650… and 0817ea80… inside a type 0x07 record | Stage linkage | Useful for chain reconstruction            |

### 13.2 Size-Based Heuristics

Containers that contain a ~24.8 KB type 0x05 record together with two type 0x09 records whose sizes differ by only a few kilobytes are strong candidates for the dual-driver generation.

### 13.3 Limitations of Static Detection

Because the large dylibs are not fully reverse-engineered here, YARA or similar rules targeting unique code sequences inside the type 0x09 modules cannot yet be proposed with high confidence. The small-data magics and the dual-f1 pattern are currently the most reliable static signals.

---

## 14. Limitations, Confidence Levels, and Alternative Hypotheses

### 14.1 Limitations

- No function-level disassembly of bootstrap.dylib or the type 0x09 drivers.  
- Internal record format of the KIEA blob beyond the magic remains unmapped.  
- Exact semantic meaning of the integer fields surrounding the SpringBoard string in entry3 is not fully established.  
- Dynamic confirmation of the low-bit selection logic inside bootstrap was not performed.

### 14.2 Confidence Ratings

| Finding                                      | Confidence |
|----------------------------------------------|------------|
| Dual type 0x09 present only in two containers | High      |
| Shared identical type 0x05 (KIEA)            | High      |
| DEADD00F magic and SpringBoard string        | High      |
| Self-referential JS filename embedding       | High      |
| Bootstrap performs low-bit selection         | Moderate-High (structural evidence strong; code confirmation absent) |
| Precise KIEA internal layout                 | Low-Moderate |

### 14.3 Alternative Hypotheses Considered

**Hypothesis A** – The two type 0x09 modules are completely independent exploits rather than primary/secondary paths.  
*Rejected*: the shared KIEA blob and near-identical surrounding records make independence unlikely.

**Hypothesis B** – The type 0x05 blob is encrypted or compressed code rather than pure data.  
*Rejected*: extensive zero-padding and the absence of any Mach-O or ARM64 header signatures argue strongly for data.

**Hypothesis C** – The DEADD00F record is a red herring or debug leftover.  
*Rejected*: it is present in both dual-driver containers and directly names the process that the type 0x0f module is known to target.

---

## 15. Conclusions and Recommendations

### 15.1 Conclusions

The dual-driver + shared KIEA constants design, together with the DEADD00F-configured SpringBoard targeting and the self-referential embedding of earlier-stage filenames, demonstrates that the authors of Coruna invested engineering effort in making the native stage maintainable across the final supported iOS 17 window. These structures are the concrete “glue” that turns a collection of powerful but brittle exploits into a coherent, multi-version implant.

The findings are original with respect to the detailed public literature available at the time of writing.

### 15.2 Recommendations for Further Research

1. Full interactive disassembly of bootstrap.dylib and both type 0x09 modules from the 377bed container, focusing on how the KIEA base address is received and indexed.  
2. Systematic extraction of all integer constants from the KIEA blob and correlation against known XNU structure layouts for iOS 17.0–17.2.1.  
3. Publication of YARA rules targeting the DEADD00F + SpringBoard and KIEA patterns.  
4. Extension of the present comparative analysis to any additional dual-driver containers that may appear in future sample sets.

### 15.3 Recommendations for Defenders

- Monitor for the static indicators listed in Section 13.  
- Treat any process that loads an unsigned or ad-hoc signed dylib into SpringBoard on iOS 17.0–17.2.1 as high priority for investigation when the earlier-stage indicators are also present.  
- Maintain awareness that community tooling has already repurposed the type 0x0f injection path; the same surface can appear in both malicious and research contexts.

---

## 16. Appendices

### Appendix A – Exact Hex Dump of entry3_type0x07.bin (49 bytes)

```
0000  0f d0 ad de 00 00 00 00 80 51 01 00 d0 07 00 00  |.........Q......|
0010  01 00 00 00 01 00 00 00 02 00 00 00 24 00 00 00  |............$...|
0020  0c 00 00 00 53 70 72 69 6e 67 42 6f 61 72 64 00  |....SpringBoard.|
0030  00                                               |.|
```

### Appendix B – Manifest Excerpt for 377bed7460f7538f96bbad7bdc2b8294bdc54599

```json
{
  "377bed7460f7538f96bbad7bdc2b8294bdc54599": [
    {"file": "entry0_type0x08.dylib", "f1": 524288, "f2": 3, "type": 8, "size": 228928},
    {"file": "entry1_type0x09.dylib", "f1": 589824, "f2": 3, "type": 9, "size": 333520},
    {"file": "entry2_type0x0f.dylib", "f1": 983040, "f2": 3, "type": 15, "size": 191296},
    {"file": "entry3_type0x07.bin", "f1": 458757, "f2": 3, "type": 7, "size": 44},
    {"file": "entry4_type0x05.bin", "f1": 327680, "f2": 3, "type": 5, "size": 24844},
    {"file": "entry5_type0x09.dylib", "f1": 589825, "f2": 3, "type": 9, "size": 330304},
    {"file": "entry6_type0x07.bin", "f1": 458752, "f2": 3, "type": 7, "size": 468}
  ]
}
```

### Appendix C – Selected Field Tables

**Type 0x07 entry3 integer fields (little-endian u32)**

| Offset | Hex Value  | Decimal | Notes                  |
|--------|------------|---------|------------------------|
| 0x00   | deadd00f   | —       | Magic                  |
| 0x08   | 00015180   | 86400   | Possibly related to timing or size |
| 0x0c   | 000007d0   | 2000    | —                      |
| 0x1c   | 00000024   | 36      | String offset          |
| 0x20   | 0000000c   | 12      | String length          |

### Appendix D – Timeline of Analysis Activity

| Date       | Activity                                                                 |
|------------|--------------------------------------------------------------------------|
| 2026-07-20 | Case opened; malware-analysis-static skill adopted; initial dual-driver observation |
| 2026-07-21 | Manifest parsing; confirmation of shared type 0x05; SpringBoard string recovery |
| 2026-07-22 | Type 0x05 KIEA magic confirmed; dual-driver evolution notes written     |
| 2026-07-23 | Precise DEADD00F layout; comparative analysis of second dual-driver container; public prior-art check; expansion of this report to intelligence-grade length |

### Appendix E – Glossary of Container Types (Observed in Dual-Driver Generation)

| Type | Typical f1   | Role                                      |
|------|--------------|-------------------------------------------|
| 0x05 | 0x50000      | Shared constants / offset tables (KIEA)   |
| 0x07 | 0x70000/05   | Configuration (process target, stage refs)|
| 0x08 | 0x80000      | Shared implant / post-exploitation        |
| 0x09 | 0x90000/01   | Kernel drivers (primary / secondary)      |
| 0x0f | 0xF0000      | Persistence / SpringBoard injection       |

---

**End of Report**

*This document is the product of pure static analysis. No binary was executed. All evidence is preserved under the case/ directory of the analysis environment. Distribution is unrestricted for defensive research purposes.*

---

**Document Control**

- Version: 1.0  
- Classification: UNCLASSIFIED // RESEARCH  
- Next review: upon acquisition of additional dual-driver samples or completion of interactive disassembly of bootstrap and type 0x09 modules.
