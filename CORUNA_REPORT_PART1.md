# CORUNA CONTAINER EVOLUTION REPORT — PART 1 of 4

**Full report lines 1–450 of 1797** | [Index](CORUNA_CONTAINER_EVOLUTION_REPORT.md) | [Part 2](CORUNA_REPORT_PART2.md)

---

# Coruna Payload Container Evolution & Module Comparative Analysis

**Classification**: UNCLASSIFIED // RESEARCH  
**Date**: 2026-07-26  
**Authors**: Static analysis (original research)  
**Repository**: https://github.com/skilfoy/coruna  
**Scope**: Complete static inventory and comparative analysis of every payload container, the Type 0x08 implant family, and Type 0x0A modules  

**Methodological note**: All findings derived from repository tree, `payloads/manifest.json`, file sizes, SHA-1 identities, and previously established F00DBEEF / DEADD00F / KIEA structures. No dynamic execution performed.

---

## 1. Executive Summary & Key Judgments

- The Coruna corpus contains **20 distinct payload containers** (including one anomalous raw.bin entry).
- These containers form **four clear architectural generations**.
- The dual-driver + shared KIEA constants design appears in **only two** containers and represents a late, deliberate redesign rather than the historical baseline.
- The DEADD00F + SpringBoard type 0x07 configuration is present across the three mature generations and is the most durable high-signal static indicator.
- Type 0x08 (post-exploitation implant) exists in at least **five distinct size/SHA variants**, showing clear evolutionary stages.
- Type 0x0A modules are concentrated in the earliest generation and in a transitional hybrid generation; they largely disappear once the dual-driver design is introduced.

**Primary judgment**: The dual-driver architecture we previously reverse-engineered is a late-stage refinement optimized for maintainability of version-specific kernel offsets. Earlier containers relied on single type 0x09 drivers (or type 0x0A paths) with offsets presumably compiled in or handled differently.

---

## 2. Comparative Container Survey — Coruna Payload Evolution

### 2.1 Taxonomy of Generations

| Generation | Designation | Defining Features | Container Count |
|------------|-------------|-------------------|-----------------|
| **A** | Early Type-0x0A | Type 0x08 + type 0x0A (bin and/or dylib). No type 0x09, no type 0x0F, no DEADD00F. | 5 |
| **B** | Classic Single Type-0x09 | Single type 0x09 + type 0x08 + type 0x0F + DEADD00F type 0x07 pair. No type 0x05, no second type 0x09. | 8 |
| **C** | Transitional (0x09 + 0x0A) | Single type 0x09 + type 0x0A dylib + type 0x08/0x0F/0x07. Still no KIEA. | 4 |
| **D** | Dual-Driver (Data-Driven) | **Two** type 0x09 (f1 0x90000 + 0x90001) + shared type 0x05 (KIEA) + type 0x08/0x0F/0x07. | 2 |
| **X** | Anomalous | Single `raw.bin` (2192 bytes). | 1 |

### 2.2 Shared Artifact Continuity

| Artifact | Identity / Size | Generations Present | Notes |
|----------|-----------------|---------------------|-------|
| DEADD00F type 0x07 (primary) | SHA `ea2db48aec8c6215bee0cedc49f084832b5090f2`, ~44–49 bytes | B, C, D | Identical across all mature containers |
| Type 0x08 (newer) | 228928 bytes, SHA `b81dd3e8d4c5d6699ae7aa4d96da9a50b79fda1a` | Late B, C, D | Dominant modern implant |
| Type 0x08 (older) | 196864 bytes, SHA `5f677b5185e0c919ba2e08901b44b5715b5e15f1` | Early B | Previous generation implant |
| Type 0x0F (newer) | 191296 bytes, SHA `e8c656a78ace2f7c6f0f13f4364cd716efb5aa93` | Late B, C, D | |
| Type 0x0F (older) | 192096 bytes, SHA `b886ab5c501d2b2cc476fc48d0fcab9b2e20328b` | Early B | |
| KIEA type 0x05 | 24844 bytes, SHA `f41d90fda2ffe35c5bc332b7944b6f0243b92ed7` | **D only** | Externalized constants table |
| Dual type 0x09 | f1=589824 (0x90000) + f1=589825 (0x90001) | **D only** | Selection by low bit of f1 |

### 2.3 Evolutionary Narrative

1. **Generation A** — Earliest recovered stage. Relies on type 0x0A modules. Smaller, less modular type 0x08. No SpringBoard-targeted DEADD00F config.
2. **Generation B** — Introduction of the modern type 0x09 kernel driver, type 0x0F persistence module, and the durable DEADD00F/SpringBoard configuration. Still one driver per container. Type 0x08 and type 0x0F themselves show an internal size evolution (older → newer).
3. **Generation C** — Hybrid packaging: a type 0x09 driver is retained while a type 0x0A dylib (~50 KB) is also carried. Suggests a transitional period in which both exploit/post-exploitation paths were distributed together.
4. **Generation D** — Data-driven redesign. Two type 0x09 variants selected at runtime by the low bit of the f1 field, plus a single shared external constants blob (KIEA). Only two containers received this architecture. Type 0x08 and type 0x0F are the newest shared versions.

This timeline is derived purely from static presence/absence and identity of the support-layer records.

---

## 3. Detailed Inventory of All Containers

### 3.1 Generation D — Dual-Driver (Data-Driven)

#### 3.1.1 `377bed7460f7538f96bbad7bdc2b8294bdc54599`
- **Type 0x08**: 228928 B (modern shared)
- **Type 0x09 primary** (f1=0x90000): 333520 B
- **Type 0x09 secondary** (f1=0x90001): 330304 B
- **Type 0x0F**: 191296 B (modern shared)
- **Type 0x07 (DEADD00F)**: present (SHA ea2db48a…)
- **Type 0x05 (KIEA)**: 24844 B (SHA f41d90fd…)
- **Type 0x07 secondary**: 468 B
- **Notes**: Largest dual-driver pair. Previously the primary subject of original dual-driver research.

#### 3.1.2 `1334417664270db20af705f422878c53c8378203`
- **Type 0x08**: 228928 B (identical)
- **Type 0x09 primary** (f1=0x90000): 284048 B
- **Type 0x09 secondary** (f1=0x90001): 263536 B
- **Type 0x0F**: 191296 B (identical)
- **Type 0x07 (DEADD00F)**: identical
- **Type 0x05 (KIEA)**: identical SHA and size
- **Type 0x07 secondary**: 468 B
- **Notes**: Second dual-driver instance. Confirms the design was applied to at least two independent containers targeting the same version window.

### 3.2 Generation C — Transitional (Type 0x09 + Type 0x0A)

#### 3.2.1 `1b2cbbde08f8b2330b7400abcb97c9573973e942`
- Type 0x08: 228928 B (modern)
- Type 0x09: 300912 B (single)
- Type 0x0F: 191296 B
- Type 0x07 DEADD00F: present
- Type 0x0A dylib: 50344 B (f1=0xA0000)
- Type 0x07 secondary: 468 B
- **No type 0x05 / no second type 0x09**

#### 3.2.2 `c8a14d79a27953242d60243ee2f505a85d9232cc`
- Type 0x08: 228928 B
- Type 0x09: 284048 B
- Type 0x0F: 191296 B
- Type 0x07 DEADD00F: present
- Type 0x0A dylib: 50344 B
- Type 0x07 secondary: 468 B

#### 3.2.3 `e9f898587620186e31119fbf32660f26c1e048e0`
- Type 0x08: 196864 B (**older** implant)
- Type 0x09: 284048 B
- Type 0x0F: 192096 B (older)
- Type 0x07 DEADD00F: present
- Type 0x0A dylib: 50344 B (different SHA)
- Type 0x07 secondary: 468 B

#### 3.2.4 `f4120dc6717a489435d86943472c5a2444aac8e6`
- Type 0x08: 228928 B
- Type 0x09: 284048 B
- Type 0x0F: 191296 B
- Type 0x07 DEADD00F: present
- Type 0x0A dylib: 50344 B
- Type 0x07 secondary: 468 B
- **Note**: Structurally identical to `c8a14d79…` in module set.

### 3.3 Generation B — Classic Single Type-0x09

#### 3.3.1 Older Type 0x08 / Type 0x0F cohort (196864 / 192096)
- `226cbd845c5f470075505392be8693ec6d4f5ba3` — type 0x09 300912 B
- `38af3c8ba461079a0edc83585023f76843066dcf` — type 0x09 284048 B
- `4800048658463f971e752ff93c1767e9ae7f3431` — type 0x09 249024 B
- `5258f6e3eef3eda249179aa1122b50b03cbeea18` — type 0x09 232256 B
- `7a1cef00016b950be42f5288ead21fa6fccc3107` — type 0x09 333504 B

All carry DEADD00F + secondary type 0x07 (468 B). No type 0x05, no dual drivers, no type 0x0A.

#### 3.3.2 Newer Type 0x08 / Type 0x0F cohort (228928 / 191296)
- `a78a94196b5d2c95865f6a8423a6b8eb86d07c6c` — type 0x09 248784 B
- `ae7efd66ecde9e964cfe92f64e9b6461fce38f28` — type 0x09 300912 B
- `b442ab113b829ff8c7bf34afa4d2d997889f308f` — type 0x09 231264 B

Same support-layer pattern as the older cohort, but with the modern implant and persistence modules.

### 3.4 Generation A — Early Type-0x0A

#### 3.4.1 Dual type 0x0A (small)
- `2a1d692b7b5ba793527b2c14b48db21a3e5d2c5f`
  - Type 0x08: 51768 B
  - Type 0x0A bin: 22660 B
  - Type 0x0A dylib: 68912 B
- `5e89f83ec50c6223d664d3f3260ef874a3d6d796`
  - Type 0x08: 51760 B (near-identical)
  - Type 0x0A bin: 22660 B (identical)
  - Type 0x0A dylib: 68912 B (identical)

#### 3.4.2 Large type 0x0A bin
- `72a5ac816709f9c331f2b3afb76cd3d96517ea14`
  - Type 0x08: 88120 B
  - Type 0x0A bin: 507450 B
- `980c77f1747afa9ac1fa5f8fbfb9e6663e9f82bb`
  - Type 0x08: 104528 B
  - Type 0x0A bin: 507450 B (identical large blob)
- `f8a86cf368fdbbe294813926a2a229df041eb758`
  - Type 0x08: 88112 B
  - Type 0x0A bin: 507450 B (identical)

**No DEADD00F, no type 0x09, no type 0x0F in any Generation A container.**

### 3.5 Anomalous
- `7a7d99099b035b2c6512b6ebeeea6df1ede70fbb` — contains only `raw.bin` (2192 B). Treated as non-standard / incomplete for the purposes of this taxonomy.

---

## 4. Type 0x08 Implant Comparative Analysis

### 4.1 Role of Type 0x08

Across the mature generations (B–D), the type 0x08 dylib is the primary post-exploitation implant loaded after successful kernel privilege escalation. It is the module that receives control from the type 0x09 driver (or, in earlier designs, from type 0x0A paths) and is responsible for subsequent actions such as:

- Establishing a stable execution environment inside the compromised process context
- Loading or coordinating the type 0x0F persistence / SpringBoard injection component
- Performing any final capability checks or environment sanitization

Because the same type 0x08 binary (by SHA) is shared across many containers, it represents one of the highest-value detection and forensic pivots in the corpus.

### 4.2 Observed Variants

Five distinct size families exist:

| Variant ID | Size (bytes) | SHA-1 | Associated Generations | # Containers |
|------------|--------------|-------|------------------------|--------------|
| **Modern Shared** | 228928 | b81dd3e8d4c5d6699ae7aa4d96da9a50b79fda1a | Late Gen B, Gen C, Gen D | 9+ |
| **Older Shared** | 196864 | 5f677b5185e0c919ba2e08901b44b5715b5e15f1 | Early Gen B | 5 |
| **Gen-A Large-A** | 104528 | e1341a854a691a1f79d33e41d5023e65184957ad | Gen A (with 507 KB 0x0A) | 1 |
| **Gen-A Mid** | 88120 / 88112 | 1d49a412… / a4f7884a… | Gen A (with 507 KB 0x0A) | 2 |
| **Gen-A Small** | 51768 / 51760 | 90753f98… / f836c402… | Gen A (dual small 0x0A) | 2 |

### 4.3 Modern vs Older Shared Implants (Primary Comparison)

The two dominant variants (228928 B and 196864 B) differ by approximately 32 KB. Both appear with the DEADD00F configuration and type 0x0F, indicating they serve the same architectural role in the post-exploitation chain.

**Key observations**:

- The 228928-byte implant is the exclusive type 0x08 used by both dual-driver containers (Gen D) and by all transitional Gen C containers that also carry the modern type 0x0F (191296 B).
- The 196864-byte implant is paired exclusively with the older type 0x0F (192096 B).
- No container mixes a modern type 0x08 with an older type 0x0F, or vice versa. The implant and persistence modules were updated as a coordinated pair.
- The size delta (~32 KB) is large enough to accommodate additional capability, new offsets, or expanded logging/anti-analysis logic, but too large to be explained by simple padding.

**Inference**: The move from the 196864-byte to the 228928-byte implant constitutes a major internal revision of the post-exploitation stage, contemporaneous with (or slightly preceding) the introduction of the dual-driver kernel stage.

### 4.4 Generation A Implants

The three smaller Gen A variants (≈51–104 KB) are substantially less complex. Their co-occurrence with type 0x0A modules (and complete absence of type 0x09 / type 0x0F / DEADD00F) indicates they belong to an earlier, less modular design in which the implant and the exploitation primitive were more tightly coupled.

### 4.5 Detection Value

Because the modern 228928-byte implant (SHA b81dd3e8…) is shared across the majority of mature containers, a single high-confidence YARA or hash rule for this binary covers Gen C, late Gen B, and both Gen D dual-driver samples. The older 196864-byte implant provides coverage for the preceding cohort.

---

## 5. Type 0x0A Module Analysis (Generations A & C)

### 5.1 Distribution

Type 0x0A records appear in two distinct contexts:

1. **Generation A (primary path)** — type 0x0A is the main (or only) exploitation / post-exploitation module.
2. **Generation C (secondary / hybrid path)** — a compact type 0x0A dylib is packaged alongside a full type 0x09 driver.

Type 0x0A is entirely absent from pure Generation B single-driver containers and from Generation D dual-driver containers.

### 5.2 Generation A Type 0x0A Variants

| Container | Type 0x0A Artifacts | Notes |
|-----------|---------------------|-------|
| `2a1d692b…` / `5e89f83e…` | 22660 B .bin + 68912 B .dylib | Near-identical pair; smallest type 0x0A set |
| `72a5ac81…` / `980c77f1…` / `f8a86cf3…` | 507450 B .bin | Identical large binary across three containers; paired with mid-size type 0x08 |

The 507450-byte type 0x0A.bin is the single largest individual module in the entire corpus outside the dual type 0x09 drivers. Its identical presence in three separate containers strongly suggests a stable, reused exploitation or payload component from the earliest recovered phase.

### 5.3 Generation C Type 0x0A

All four Gen C containers carry a type 0x0A dylib of exactly 50344 bytes (f1 = 0xA0000). Two distinct SHAs are observed, indicating at least one internal revision of this compact module.

In Gen C the type 0x0A dylib coexists with a complete modern (or near-modern) type 0x09 + type 0x0F + DEADD00F stack. This is the clearest evidence of a transitional packaging strategy: the operators distributed both the older type 0x0A path and the newer type 0x09 path in the same container, presumably to maximize compatibility or to retain a fallback.

### 5.4 Disappearance in Later Generations

Once the dual-driver design (Gen D) is introduced, type 0x0A records vanish. The data-driven type 0x09 pair + shared KIEA constants appear to have fully superseded the earlier type 0x0A approach for the version window targeted by those two containers.

### 5.5 Analytical Limits

Without interactive disassembly, the precise capability differences between the 50 KB Gen C type 0x0A dylib and the much larger Gen A 507 KB type 0x0A.bin remain opaque. The size disparity alone indicates they are not simple revisions of the same module.

---

**Continue to [Part 2](CORUNA_REPORT_PART2.md)**
