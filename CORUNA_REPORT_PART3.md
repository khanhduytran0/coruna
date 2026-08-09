# CORUNA CONTAINER EVOLUTION REPORT — PART 3 of 4

**Full report lines 901–1350 of 1797** | [Index](CORUNA_CONTAINER_EVOLUTION_REPORT.md) | [Part 2](CORUNA_REPORT_PART2.md) | [Part 4](CORUNA_REPORT_PART4.md)

---

# PRIORITY 1 COMPLETION — FULL GENERATION B TECHNICAL INVENTORY

Generation B is the largest cohort. Complete per-container entry structure and size-clustering analysis.

## 3.3 Generation B — Classic Single Type-0x09 (Complete)

Defined by invariant structure:
- Exactly one type 0x09 record (f1 = 0x90000)
- One type 0x08 implant
- One type 0x0F persistence module
- DEADD00F primary type 0x07 (f1 = 0x70005)
- Secondary type 0x07 (f1 = 0x70000)
- No type 0x05 (KIEA)
- No second type 0x09
- No type 0x0A

Two sub-cohorts distinguished by which coordinated implant/persistence pair is present.

### 3.3.1 Older Implant/Persistence Cohort

All five use type 0x08 = 196864 B (SHA 5f677b5185e0c919ba2e08901b44b5715b5e15f1) and type 0x0F = 192096 B (SHA b886ab5c501d2b2cc476fc48d0fcab9b2e20328b).

#### Container 226cbd845c5f470075505392be8693ec6d4f5ba3

| Entry | Filename | f1 (hex) | Type | Size | SHA-1 / Notes |
|-------|----------|----------|------|------|---------------|
| entry0 | entry0_type0x08.dylib | 0x80000 | 0x08 | 196864 | 5f677b51… (older shared implant) |
| entry1 | entry1_type0x09.dylib | 0x90000 | 0x09 | 300912 | 2a446a3b89acca0f1baaf01b7bc69e83242615cb |
| entry2 | entry2_type0x0f.dylib | 0xF0000 | 0x0F | 192096 | b886ab5c… (older shared persistence) |
| entry3 | entry3_type0x07.bin | 0x70005 | 0x07 | 44 | ea2db48a… (DEADD00F, universal) |
| entry4 | entry4_type0x07.bin | 0x70000 | 0x07 | 468 | secondary config |

#### Container 38af3c8ba461079a0edc83585023f76843066dcf

| Entry | Filename | f1 (hex) | Type | Size | SHA-1 / Notes |
|-------|----------|----------|------|------|---------------|
| entry0 | entry0_type0x08.dylib | 0x80000 | 0x08 | 196864 | 5f677b51… |
| entry1 | entry1_type0x09.dylib | 0x90000 | 0x09 | 284048 | fa7f7a9e84299b654d9eb5f54d09ead4c5a696c3 |
| entry2 | entry2_type0x0f.dylib | 0xF0000 | 0x0F | 192096 | b886ab5c… |
| entry3 | entry3_type0x07.bin | 0x70005 | 0x07 | 44 | ea2db48a… |
| entry4 | entry4_type0x07.bin | 0x70000 | 0x07 | 468 | secondary config |

Type 0x09 size 284048 also appears in Gen C and as dual-driver primary — one of the more frequently reused driver sizes.

#### Container 4800048658463f971e752ff93c1767e9ae7f3431

| Entry | Filename | f1 (hex) | Type | Size | SHA-1 / Notes |
|-------|----------|----------|------|------|---------------|
| entry0 | entry0_type0x08.dylib | 0x80000 | 0x08 | 196864 | 5f677b51… |
| entry1 | entry1_type0x09.dylib | 0x90000 | 0x09 | 249024 | 1f084486add0b36a9c28d7862003748f6214fa52 |
| entry2 | entry2_type0x0f.dylib | 0xF0000 | 0x0F | 192096 | b886ab5c… |
| entry3 | entry3_type0x07.bin | 0x70005 | 0x07 | 44 | ea2db48a… |
| entry4 | entry4_type0x07.bin | 0x70000 | 0x07 | 468 | secondary config |

#### Container 5258f6e3eef3eda249179aa1122b50b03cbeea18

| Entry | Filename | f1 (hex) | Type | Size | SHA-1 / Notes |
|-------|----------|----------|------|------|---------------|
| entry0 | entry0_type0x08.dylib | 0x80000 | 0x08 | 196864 | 5f677b51… |
| entry1 | entry1_type0x09.dylib | 0x90000 | 0x09 | 232256 | 2c3b7f3f627d968e996790a0d1a9ef7ab16aac73 |
| entry2 | entry2_type0x0f.dylib | 0xF0000 | 0x0F | 192096 | b886ab5c… |
| entry3 | entry3_type0x07.bin | 0x70005 | 0x07 | 44 | ea2db48a… |
| entry4 | entry4_type0x07.bin | 0x70000 | 0x07 | 468 | secondary config |

#### Container 7a1cef00016b950be42f5288ead21fa6fccc3107

| Entry | Filename | f1 (hex) | Type | Size | SHA-1 / Notes |
|-------|----------|----------|------|------|---------------|
| entry0 | entry0_type0x08.dylib | 0x80000 | 0x08 | 196864 | 5f677b51… |
| entry1 | entry1_type0x09.dylib | 0x90000 | 0x09 | 333504 | c90bbcb57de6bd2010de6e074db74645fce63e59 |
| entry2 | entry2_type0x0f.dylib | 0xF0000 | 0x0F | 192096 | b886ab5c… |
| entry3 | entry3_type0x07.bin | 0x70005 | 0x07 | 44 | ea2db48a… |
| entry4 | entry4_type0x07.bin | 0x70000 | 0x07 | 468 | secondary config |

Largest single-driver type 0x09 recovered anywhere (333504 B). Only 16 bytes smaller than largest dual-driver primary (333520). High-water mark of inlined complexity before externalisation of constants into KIEA.

### 3.3.2 Newer Implant/Persistence Cohort

All three use type 0x08 = 228928 B (SHA b81dd3e8d4c5d6699ae7aa4d96da9a50b79fda1a) and type 0x0F = 191296 B (SHA e8c656a78ace2f7c6f0f13f4364cd716efb5aa93).

#### Container a78a94196b5d2c95865f6a8423a6b8eb86d07c6c

| Entry | Filename | f1 (hex) | Type | Size | SHA-1 / Notes |
|-------|----------|----------|------|------|---------------|
| entry0 | entry0_type0x08.dylib | 0x80000 | 0x08 | 228928 | b81dd3e8… (modern shared implant) |
| entry1 | entry1_type0x09.dylib | 0x90000 | 0x09 | 248784 | a1f063ddaa80b095b95dbe0687d435dd62801950 |
| entry2 | entry2_type0x0f.dylib | 0xF0000 | 0x0F | 191296 | e8c656a7… (modern shared persistence) |
| entry3 | entry3_type0x07.bin | 0x70005 | 0x07 | 44 | ea2db48a… |
| entry4 | entry4_type0x07.bin | 0x70000 | 0x07 | 468 | secondary config |

#### Container ae7efd66ecde9e964cfe92f64e9b6461fce38f28

| Entry | Filename | f1 (hex) | Type | Size | SHA-1 / Notes |
|-------|----------|----------|------|------|---------------|
| entry0 | entry0_type0x08.dylib | 0x80000 | 0x08 | 228928 | b81dd3e8… |
| entry1 | entry1_type0x09.dylib | 0x90000 | 0x09 | 300912 | a284d84fbdd4b6c0613769047f8f4f2f55d91f9e |
| entry2 | entry2_type0x0f.dylib | 0xF0000 | 0x0F | 191296 | e8c656a7… |
| entry3 | entry3_type0x07.bin | 0x70005 | 0x07 | 44 | ea2db48a… |
| entry4 | entry4_type0x07.bin | 0x70000 | 0x07 | 468 | secondary config |

Type 0x09 size 300912 also appears in older cohort and Gen C — most frequently reused type 0x09 size across generational boundaries.

#### Container b442ab113b829ff8c7bf34afa4d2d997889f308f

| Entry | Filename | f1 (hex) | Type | Size | SHA-1 / Notes |
|-------|----------|----------|------|------|---------------|
| entry0 | entry0_type0x08.dylib | 0x80000 | 0x08 | 228928 | b81dd3e8… |
| entry1 | entry1_type0x09.dylib | 0x90000 | 0x09 | 231264 | 564da86d6a85927ad58f328e5abafb7a458bbcef |
| entry2 | entry2_type0x0f.dylib | 0xF0000 | 0x0F | 191296 | e8c656a7… |
| entry3 | entry3_type0x07.bin | 0x70005 | 0x07 | 44 | ea2db48a… |
| entry4 | entry4_type0x07.bin | 0x70000 | 0x07 | 468 | secondary config |

Smallest type 0x09 in any mature container (231264 B).

### 3.3.3 Generation B Type 0x09 Size Clustering Analysis

Eight containers contain seven distinct type 0x09 sizes ranging 231264–333504 bytes. Key observations:

1. At least seven distinct driver builds inside one generation — direct evidence of the maintenance problem dual-driver was meant to solve.
2. Size range ~100 KB accommodates substantial differences in inlined offsets, gadget sets, or version-specific paths.
3. Size 300912 crosses the older/newer implant boundary — driver revision and implant revision were not perfectly synchronised.
4. Largest single-driver (333504) is only 16 bytes smaller than largest dual-driver primary (333520) — redesign reduced *number* of builds, not individual binary size.

### 3.3.4 Secondary Type 0x07 Configuration Variability

Primary DEADD00F (44 B, SHA ea2db48a…) is identical across all mature containers. Secondary type 0x07 (468 B) shows multiple distinct SHAs — lower-signal indicator, likely per-container or per-campaign configuration.

### 3.3.5 Generation B Summary Judgment

Classic single-driver architecture already required a non-trivial number of distinct type 0x09 builds for version coverage. Later dual-driver selectable pair + shared external constants is best understood as a direct response to the maintenance cost visible in this generation.

---

# EXPANDED SECTION 6 — EVOLUTIONARY TIMELINE AND DESIGN RATIONALE

## 6.1 Relative Chronology

```
Gen A (earliest)
  └─ Type 0x0A primary + small/mid type 0x08
       │
Gen B (classic)
  └─ Single type 0x09 + DEADD00F + type 0x0F
       │   (internal update: type 0x08 196 KB → 228 KB;
       │                    type 0x0F 192 KB → 191 KB)
       │
Gen C (transitional)
  └─ Single type 0x09 + DEADD00F + type 0x0F
       + retained compact type 0x0A dylib (~50 KB)
       │
Gen D (data-driven)
  └─ Dual type 0x09 (f1 low-bit select)
       + shared KIEA type 0x05 constants
       + modern type 0x08 / type 0x0F
       (type 0x0A eliminated)
```

## 6.2 Design Pressure Visible in Generation B

Generation B already required ≥7 distinct type 0x09 binaries (231–333 KB). Each new iOS point release changing kernel offsets or PAC gadgets required a new full driver build or invasive binary patching. Packaging and distributing many near-duplicate multi-hundred-kilobyte drivers is operationally expensive and increases forensic footprint.

## 6.3 Selective Application of the Dual-Driver Design

Only two containers received dual-driver treatment. Redesign applied late and selectively; not retrofitted to earlier corpus. Consistent with opportunistic improvement rather than wholesale rewrite.

Generation D attacks the cost directly:
- Two driver variants instead of many
- Version-specific data externalised into one shared 24 KB KIEA blob
- Selection reduced to a single bit test on f1
- Same KIEA blob pairable with different driver builds (demonstrated by the two dual-driver containers)

---

# EXPANDED SECTION 7 — DETECTION IMPLICATIONS AND RULE SETS

## 7.1 High-Value Static Indicators (Ranked)

| Rank | Indicator | Coverage | Uniqueness | Ease of Match |
|------|-----------|----------|------------|---------------|
| 1 | DEADD00F magic + "SpringBoard" (≤64 B) | Gen B, C, D | Extremely high | Trivial |
| 2 | Type 0x08 modern SHA / exact 228928 B | Late B, C, D | Extremely high | Trivial |
| 3 | Type 0x08 older SHA / exact 196864 B | Early B (+1 C) | Extremely high | Trivial |
| 4 | KIEA magic at offset 0 + exact 24844 B | Gen D only | Extremely high | Trivial |
| 5 | Simultaneous f1 0x90000 + 0x90001 | Gen D only | Extremely high | Requires container parse |
| 6 | Type 0x0F modern / older size+SHA pairs | Paired with 2/3 | High | Trivial |
| 7 | Type 0x0A 507450 B blob | Gen A (3) | High | Trivial |
| 8 | Type 0x0A 50344 B dylib (f1 0xA0000) | Gen C | Medium-High | Easy |
| 9 | Secondary type 0x07 468 B variants | All mature | Low-Medium | Easy but noisy |

## 7.2 Recommended YARA Rules (Extended)

```yara
rule Coruna_DEADD00F_SpringBoard
{
    meta:
        description = "Coruna type 0x07 DEADD00F + SpringBoard configuration"
        author = "original research"
        date = "2026-07-26"
        confidence = "high"
        coverage = "Generations B, C, D"
    strings:
        $magic = { 0F D0 AD DE }
        $sb1 = "SpringBoard" ascii
        $sb2 = "SpringBoard" wide
    condition:
        $magic at 0 and any of ($sb*) and filesize < 80
}

rule Coruna_KIEA_Constants_Blob
{
    meta:
        description = "Coruna shared KIEA type 0x05 constants table"
        author = "original research"
        date = "2026-07-26"
        confidence = "high"
        coverage = "Generation D only"
    strings:
        $kiea = "KIEA" ascii fullword
    condition:
        $kiea at 0 and filesize == 24844
}

rule Coruna_Type08_Modern_Implant
{
    meta:
        description = "Coruna modern type 0x08 post-exploitation implant"
        author = "original research"
        date = "2026-07-26"
        confidence = "high"
        coverage = "Late Gen B, Gen C, Gen D"
    condition:
        filesize == 228928
}

rule Coruna_Type08_Older_Implant
{
    meta:
        description = "Coruna older type 0x08 post-exploitation implant"
        author = "original research"
        date = "2026-07-26"
        confidence = "high"
        coverage = "Early Gen B (+ one Gen C)"
    condition:
        filesize == 196864
}

rule Coruna_Type0A_Large_GenA
{
    meta:
        description = "Coruna Generation A large type 0x0A.bin"
        author = "original research"
        date = "2026-07-26"
        confidence = "high"
        coverage = "Generation A (three containers)"
    condition:
        filesize == 507450
}

rule Coruna_Type0A_Compact_GenC
{
    meta:
        description = "Coruna Generation C compact type 0x0A dylib"
        author = "original research"
        date = "2026-07-26"
        confidence = "medium-high"
        coverage = "Generation C"
    condition:
        filesize == 50344
}
```

---

# CONFIDENCE MATRIX, RELATED WORK, KEY JUDGMENTS

## Confidence Matrix

| Finding | Confidence | Basis |
|---------|------------|-------|
| Four-generation taxonomy (A/B/C/D) | High | Complete enumeration; consistent presence/absence |
| DEADD00F identity across B/C/D | High | Identical SHA from every mature container |
| KIEA shared only by two Gen D containers | High | Identical size + SHA; absent elsewhere |
| Dual type 0x09 selection by f1 low bit | High | Manifest f1 values; structural necessity |
| Coordinated modern/older type 0x08/0x0F pairing | High | No mixed pairings across 15+ containers |
| Type 0x0A eliminated in Gen D | High | Complete absence from both dual-driver containers |
| Type 0x09 size proliferation as design pressure | Medium-High | Observed 231–333 KB range across ≥7 binaries |
| Exact content of 32 KB type 0x08 delta | Low | Requires interactive disassembly |
| Precise KIEA internal layout beyond magic | Low | Requires kernelcache correlation |
| Absolute chronological dating | Low | Only relative order supported |

## Formal Key Judgments

1. Dual-driver architecture (two type 0x09 variants selected by f1 low bit + shared external KIEA) is a late-stage engineering refinement, not the historical baseline. It appears in only two of twenty recovered containers.

2. DEADD00F + SpringBoard type 0x07 configuration is the single most durable high-signal static indicator across the mature corpus (Generations B, C and D).

3. Type 0x08 (implant) and type 0x0F (persistence) were revised as a coordinated pair. The modern 228928-byte implant is never observed with the older 192096-byte persistence module, and vice versa.

4. Type 0x0A served as the primary path in the earliest recovered generation and was retained as a secondary/fallback path during a transitional period; it was eliminated once the dual-driver design was introduced.

5. The proliferation of distinct type 0x09 binary sizes inside Generation B (231–333 KB) constitutes direct evidence of the maintenance cost that the dual-driver + shared-constants design was intended to amortize.

## Recommendations for Further Static Work

1. Interactive Mach-O analysis of modern versus older type 0x08 implants to identify the concrete contents of the 32 KB delta.
2. Extraction of the first several hundred bytes of the KIEA blob followed by correlation against known XNU structure layouts for iOS 17.0–17.2.1.
3. Comparative string and import analysis of the 507450-byte Generation A type 0x0A.bin against the 50344-byte Generation C type 0x0A dylib.
4. Full export-trie and load-command inspection of bootstrap.dylib to confirm the precise selection and constants-passing logic that activates only when both 0x90000 and 0x90001 records are present.

---

**Continue to [Part 4](CORUNA_REPORT_PART4.md)**
