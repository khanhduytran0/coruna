# CORUNA CONTAINER EVOLUTION REPORT — PART 2 of 4

**Full report lines 451–900 of 1797** | [Index](CORUNA_CONTAINER_EVOLUTION_REPORT.md) | [Part 1](CORUNA_REPORT_PART1.md) | [Part 3](CORUNA_REPORT_PART3.md)

---

# FULL EXPANDED SECTION 3 — COMPLETE TECHNICAL INVENTORY OF ALL CONTAINERS

This expanded inventory provides exhaustive static inventory of every payload container. For each container the complete F00DBEEF entry list is given with f1 values, types, sizes and SHA-1 identities.

## 3.1 Generation D — Dual-Driver Containers (Complete Entry Tables)

### 3.1.1 Container 377bed7460f7538f96bbad7bdc2b8294bdc54599

| # | Filename | f1 (hex) | Type | Size | SHA-1 |
|---|----------|----------|------|------|-------|
| 0 | entry0_type0x08.dylib | 0x80000 | 0x08 | 228928 | b81dd3e8d4c5d6699ae7aa4d96da9a50b79fda1a |
| 1 | entry1_type0x09.dylib | 0x90000 | 0x09 | 333520 | 603f703de67c3ead9614c780224153e37e5fcd3b |
| 2 | entry2_type0x0f.dylib | 0xF0000 | 0x0F | 191296 | e8c656a78ace2f7c6f0f13f4364cd716efb5aa93 |
| 3 | entry3_type0x07.bin | 0x70005 | 0x07 | 44 | ea2db48aec8c6215bee0cedc49f084832b5090f2 |
| 4 | entry4_type0x05.bin | 0x50000 | 0x05 | 24844 | f41d90fda2ffe35c5bc332b7944b6f0243b92ed7 |
| 5 | entry5_type0x09.dylib | 0x90001 | 0x09 | 330304 | aace95993995df8c01194f68d1203081c6b9a6bc |
| 6 | entry6_type0x07.bin | 0x70000 | 0x07 | 468 | 629744abf54ff0cbbaf463fa4ff8100192eea933 |

Primary driver is the largest type 0x09 in the corpus (333520 B). KIEA, type 0x08, type 0x0F and DEADD00F are the modern shared identities.

### 3.1.2 Container 1334417664270db20af705f422878c53c8378203

| # | Filename | f1 (hex) | Type | Size | SHA-1 |
|---|----------|----------|------|------|-------|
| 0 | entry0_type0x08.dylib | 0x80000 | 0x08 | 228928 | b81dd3e8d4c5d6699ae7aa4d96da9a50b79fda1a |
| 1 | entry1_type0x09.dylib | 0x90000 | 0x09 | 284048 | 172b89e4fd8be280eb0d8ff6744941e995816c63 |
| 2 | entry2_type0x0f.dylib | 0xF0000 | 0x0F | 191296 | e8c656a78ace2f7c6f0f13f4364cd716efb5aa93 |
| 3 | entry3_type0x07.bin | 0x70005 | 0x07 | 44 | ea2db48aec8c6215bee0cedc49f084832b5090f2 |
| 4 | entry4_type0x05.bin | 0x50000 | 0x05 | 24844 | f41d90fda2ffe35c5bc332b7944b6f0243b92ed7 |
| 5 | entry5_type0x09.dylib | 0x90001 | 0x09 | 263536 | 0cfd609835402e89cccee0a36b31bbd8087cd663 |
| 6 | entry6_type0x07.bin | 0x70000 | 0x07 | 468 | 60b91ea5178e92498b529a47182868c1244b024b |

Second dual-driver instance. Identical KIEA/0x08/0x0F/DEADD00F. Different driver sizes prove KIEA is designed to be shared across multiple driver builds.

## 3.2 Generation C — Transitional (Complete)

### 3.2.1 Container 1b2cbbde08f8b2330b7400abcb97c9573973e942

| # | Filename | f1 (hex) | Type | Size | SHA-1 |
|---|----------|----------|------|------|-------|
| 0 | entry0_type0x08.dylib | 0x80000 | 0x08 | 228928 | b81dd3e8d4c5d6699ae7aa4d96da9a50b79fda1a |
| 1 | entry1_type0x09.dylib | 0x90000 | 0x09 | 300912 | a284d84fbdd4b6c0613769047f8f4f2f55d91f9e |
| 2 | entry2_type0x0f.dylib | 0xF0000 | 0x0F | 191296 | e8c656a78ace2f7c6f0f13f4364cd716efb5aa93 |
| 3 | entry3_type0x07.bin | 0x70005 | 0x07 | 44 | ea2db48aec8c6215bee0cedc49f084832b5090f2 |
| 4 | entry4_type0x0a.dylib | 0xA0000 | 0x0A | 50344 | f53bc3d1b239168e69a51ac67d86ca4c56aa1beb |
| 5 | entry5_type0x07.bin | 0x70000 | 0x07 | 468 | 15f4077e0d802a2c3abc3e79ea96e8aeb2bec119 |

### 3.2.2 Container c8a14d79a27953242d60243ee2f505a85d9232cc

| # | Filename | f1 (hex) | Type | Size | SHA-1 |
|---|----------|----------|------|------|-------|
| 0 | entry0_type0x08.dylib | 0x80000 | 0x08 | 228928 | b81dd3e8d4c5d6699ae7aa4d96da9a50b79fda1a |
| 1 | entry1_type0x09.dylib | 0x90000 | 0x09 | 284048 | 172b89e4fd8be280eb0d8ff6744941e995816c63 |
| 2 | entry2_type0x0f.dylib | 0xF0000 | 0x0F | 191296 | e8c656a78ace2f7c6f0f13f4364cd716efb5aa93 |
| 3 | entry3_type0x07.bin | 0x70005 | 0x07 | 44 | ea2db48aec8c6215bee0cedc49f084832b5090f2 |
| 4 | entry4_type0x0a.dylib | 0xA0000 | 0x0A | 50344 | f53bc3d1b239168e69a51ac67d86ca4c56aa1beb |
| 5 | entry5_type0x07.bin | 0x70000 | 0x07 | 468 | 60b91ea5178e92498b529a47182868c1244b024b |

### 3.2.3 Container e9f898587620186e31119fbf32660f26c1e048e0

Uses **older** type 0x08/0x0F pair while still carrying type 0x0A.

| # | Filename | f1 (hex) | Type | Size | SHA-1 |
|---|----------|----------|------|------|-------|
| 0 | entry0_type0x08.dylib | 0x80000 | 0x08 | 196864 | 5f677b5185e0c919ba2e08901b44b5715b5e15f1 |
| 1 | entry1_type0x09.dylib | 0x90000 | 0x09 | 284048 | fa7f7a9e84299b654d9eb5f54d09ead4c5a696c3 |
| 2 | entry2_type0x0f.dylib | 0xF0000 | 0x0F | 192096 | b886ab5c501d2b2cc476fc48d0fcab9b2e20328b |
| 3 | entry3_type0x07.bin | 0x70005 | 0x07 | 44 | ea2db48aec8c6215bee0cedc49f084832b5090f2 |
| 4 | entry4_type0x0a.dylib | 0xA0000 | 0x0A | 50344 | 5fa390b9e291824fde40cdd76ac85b67ccb8ee0f |
| 5 | entry5_type0x07.bin | 0x70000 | 0x07 | 468 | 60b91ea5178e92498b529a47182868c1244b024b |

### 3.2.4 Container f4120dc6717a489435d86943472c5a2444aac8e6

Module set essentially identical to c8a14d79…

| # | Filename | f1 (hex) | Type | Size | SHA-1 |
|---|----------|----------|------|------|-------|
| 0 | entry0_type0x08.dylib | 0x80000 | 0x08 | 228928 | b81dd3e8d4c5d6699ae7aa4d96da9a50b79fda1a |
| 1 | entry1_type0x09.dylib | 0x90000 | 0x09 | 284048 | 172b89e4fd8be280eb0d8ff6744941e995816c63 |
| 2 | entry2_type0x0f.dylib | 0xF0000 | 0x0F | 191296 | e8c656a78ace2f7c6f0f13f4364cd716efb5aa93 |
| 3 | entry3_type0x07.bin | 0x70005 | 0x07 | 44 | ea2db48aec8c6215bee0cedc49f084832b5090f2 |
| 4 | entry4_type0x0a.dylib | 0xA0000 | 0x0A | 50344 | f53bc3d1b239168e69a51ac67d86ca4c56aa1beb |
| 5 | entry5_type0x07.bin | 0x70000 | 0x07 | 468 | 60b91ea5178e92498b529a47182868c1244b024b |

Generation C summary: all four retain 50344-byte type 0x0A dylib at f1 0xA0000; two distinct SHAs; three use modern implant pair, one uses older; no type 0x05.

## 3.3 Generation B — Classic Single Type-0x09 (Complete)

Invariant structure: exactly one type 0x09 (f1 0x90000), one type 0x08, one type 0x0F, DEADD00F primary (0x70005), secondary type 0x07 (0x70000). No type 0x05, no second type 0x09, no type 0x0A.

### 3.3.1 Older Cohort (type 0x08 = 196864 B, type 0x0F = 192096 B)

- **226cbd845c5f470075505392be8693ec6d4f5ba3** — type 0x09 300912 B (SHA 2a446a3b89acca0f1baaf01b7bc69e83242615cb)
- **38af3c8ba461079a0edc83585023f76843066dcf** — type 0x09 284048 B (SHA fa7f7a9e84299b654d9eb5f54d09ead4c5a696c3)
- **4800048658463f971e752ff93c1767e9ae7f3431** — type 0x09 249024 B (SHA 1f084486add0b36a9c28d7862003748f6214fa52)
- **5258f6e3eef3eda249179aa1122b50b03cbeea18** — type 0x09 232256 B (SHA 2c3b7f3f627d968e996790a0d1a9ef7ab16aac73)
- **7a1cef00016b950be42f5288ead21fa6fccc3107** — type 0x09 333504 B (SHA c90bbcb57de6bd2010de6e074db74645fce63e59) — largest single-driver type 0x09 in corpus

### 3.3.2 Newer Cohort (type 0x08 = 228928 B, type 0x0F = 191296 B)

- **a78a94196b5d2c95865f6a8423a6b8eb86d07c6c** — type 0x09 248784 B (SHA a1f063ddaa80b095b95dbe0687d435dd62801950)
- **ae7efd66ecde9e964cfe92f64e9b6461fce38f28** — type 0x09 300912 B (SHA a284d84fbdd4b6c0613769047f8f4f2f55d91f9e)
- **b442ab113b829ff8c7bf34afa4d2d997889f308f** — type 0x09 231264 B (SHA 564da86d6a85927ad58f328e5abafb7a458bbcef) — smallest mature type 0x09

### 3.3.3 Type 0x09 Size Distribution (Generation B)

| Size (bytes) | Count | Cohort | Notes |
|--------------|-------|--------|-------|
| 333504 | 1 | Older | Largest single-driver; near dual-driver max |
| 300912 | 2 | Both | Most reused size across cohorts |
| 284048 | 1 | Older | Also appears in Gen C and Gen D primary |
| 249024 | 1 | Older | Unique |
| 248784 | 1 | Newer | Unique |
| 232256 | 1 | Older | Unique |
| 231264 | 1 | Newer | Smallest mature type 0x09 |

Even inside a single generation the operators maintained at least seven distinct driver builds. This is direct evidence of the version-coverage / maintenance problem that the later dual-driver design was intended to solve. The size range (231–333 KB) is ~100 KB — large enough for substantial differences in inlined offsets, gadget sets, or version-specific code paths. The largest single-driver binary (333504) is only 16 bytes smaller than the largest dual-driver primary (333520), suggesting the redesign reduced the *number* of full builds rather than dramatically shrinking individual drivers.

## 3.4 Generation A — Early Type-0x0A

### 3.4.1 Dual Small Type-0x0A

Containers 2a1d692b… and 5e89f83e… share identical 22660-byte type 0x0A.bin and 68912-byte type 0x0A.dylib. Type 0x08 implants are the smallest recovered (≈51.7 KB).

### 3.4.2 Large Type-0x0A.bin

Containers 72a5ac81…, 980c77f1… and f8a86cf3… share an identical 507450-byte type 0x0A.bin — the largest non-driver module in the corpus. Type 0x08 sizes in this sub-cohort are 88–104 KB.

## 3.5 Anomalous

Container 7a7d99099b035b2c6512b6ebeeea6df1ede70fbb — only raw.bin (2192 B).

## 3.6 Cross-Cutting Structural Conclusions

1. DEADD00F + SpringBoard is the most durable high-signal artifact across mature generations (B, C, D).
2. Modern type 0x08 / type 0x0F pair was introduced as a coordinated revision; no container mixes modern implant with older persistence or vice versa.
3. Type 0x0A is present in earliest generation as primary path and retained as secondary in transitional generation; eliminated once dual-driver appears.
4. Dual-driver + KIEA appears late and only in two containers — opportunistic improvement, not wholesale rewrite.
5. f1 values are used consistently as a type + role namespace across the entire corpus.

---

# EXPANDED SECTION 4 — TYPE 0x08 IMPLANT COMPARATIVE ANALYSIS (FULL)

## 4.1 Architectural Role

The type 0x08 dylib is the primary post-exploitation implant. After the type 0x09 kernel driver (or earlier type 0x0A path) obtains elevated privileges, control transfers to type 0x08. It stabilises the execution environment, coordinates type 0x0F persistence, performs final capability checks, and serves as long-lived presence.

## 4.2 Complete Variant Catalogue

### Variant M — Modern Shared Implant
- Size: 228928 bytes
- SHA-1: b81dd3e8d4c5d6699ae7aa4d96da9a50b79fda1a
- Generations: late Gen B, Gen C (modern persistence), both Gen D
- Count: ≥9
- Paired exclusively with type 0x0F 191296 B (SHA e8c656a78ace2f7c6f0f13f4364cd716efb5aa93)

### Variant O — Older Shared Implant
- Size: 196864 bytes
- SHA-1: 5f677b5185e0c919ba2e08901b44b5715b5e15f1
- Generations: early Gen B, one Gen C
- Count: 6
- Paired exclusively with type 0x0F 192096 B (SHA b886ab5c501d2b2cc476fc48d0fcab9b2e20328b)

### Variant A1 — Generation A Small
- Sizes: 51768 / 51760 bytes
- Generations: A only (dual small type 0x0A)

### Variant A2 — Generation A Mid
- Sizes: 88120 / 88112 bytes
- Generations: A only (large type 0x0A.bin)

### Variant A3 — Generation A Larger
- Size: 104528 bytes
- Generations: A only

## 4.3 Modern vs Older Shared Implant — Detailed Comparison

Delta: 32064 bytes (~32 KB). Both appear exclusively with DEADD00F and type 0x0F.

**Critical pairing rule**: Modern type 0x08 always with modern type 0x0F; older always with older. No mixed pairings exist across the entire corpus. Implant and persistence module were revised as a coordinated unit.

The 32 KB delta is too large for padding or compiler settings. Consistent with new capability, expanded offset tables, additional logging/anti-analysis, or broader iOS version support.

## 4.4 Generation A Implants

Three smaller variants (≈51–104 KB) are substantially less complex. Exclusive co-occurrence with type 0x0A and absence of type 0x09/0x0F/DEADD00F indicates earlier design with tighter coupling between implant and exploitation primitive. No reuse in later generations.

## 4.5 Detection Value of Type 0x08

Variant M covers both dual-driver containers, all late Gen B, and three of four Gen C. Variant O covers the preceding cohort. Together: near-complete coverage of every container using the modern support-layer design.

---

# EXPANDED SECTION 5 — TYPE 0x0A MODULE ANALYSIS (FULL)

## 5.1 Distribution and Role

1. Generation A — type 0x0A is the primary (often sole) path.
2. Generation C — compact type 0x0A dylib retained alongside full type 0x09 + type 0x0F + DEADD00F stack.

Absent from pure Gen B and both Gen D containers.

## 5.2 Generation A Type 0x0A Variants

**Small dual set**: 22660 B .bin (SHA 7424d4f5…) + 68912 B .dylib (SHA 2d3c4a95…) in containers 2a1d692b… and 5e89f83e…

**Large singleton**: 507450 B .bin (SHA 907e8d19…) identical in containers 72a5ac81…, 980c77f1…, f8a86cf3…. Largest individual non-driver module in the corpus. Stable reused component from earliest recovered phase.

## 5.3 Generation C Type 0x0A

All four Gen C containers: type 0x0A dylib exactly 50344 bytes at f1 0xA0000. Two SHAs:
- f53bc3d1b239168e69a51ac67d86ca4c56aa1beb (three containers)
- 5fa390b9e291824fde40cdd76ac85b67ccb8ee0f (one container)

Clearest evidence of transitional packaging: both older type 0x0A path and newer type 0x09 path distributed together for compatibility or fallback.

## 5.4 Elimination in Generation D

Type 0x0A records vanish completely once dual-driver design is introduced. Data-driven type 0x09 pair + shared KIEA fully supersede the earlier type 0x0A approach for the targeted version window.

## 5.5 Analytical Limits

Without interactive disassembly the precise functional relationship between the 50 KB Gen C dylib and the 507 KB Gen A .bin cannot be established. Size disparity alone shows they are not simple revisions of the same module.

---

**Continue to [Part 3](CORUNA_REPORT_PART3.md)**
