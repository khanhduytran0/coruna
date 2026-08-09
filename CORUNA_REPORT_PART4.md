# CORUNA CONTAINER EVOLUTION REPORT — PART 4 of 4

**Full report lines 1351–1797 of 1797** | [Index](CORUNA_CONTAINER_EVOLUTION_REPORT.md) | [Part 3](CORUNA_REPORT_PART3.md)

---

# PRIORITY 5 — FULL DETECTION SECTION (COMPLETE)

## 7.3 Hash-Based Detection Lists

Exact SHA-1 values for the highest-value shared modules:

**Type 0x08 Implants**
- Modern: `b81dd3e8d4c5d6699ae7aa4d96da9a50b79fda1a` (228928 B)
- Older: `5f677b5185e0c919ba2e08901b44b5715b5e15f1` (196864 B)

**Type 0x0F Persistence**
- Modern: `e8c656a78ace2f7c6f0f13f4364cd716efb5aa93` (191296 B)
- Older: `b886ab5c501d2b2cc476fc48d0fcab9b2e20328b` (192096 B)

**KIEA Constants**
- `f41d90fda2ffe35c5bc332b7944b6f0243b92ed7` (24844 B)

**DEADD00F Primary Config**
- `ea2db48aec8c6215bee0cedc49f084832b5090f2` (~44–49 B)

**Type 0x0A Large (Gen A)**
- `907e8d190d7c7bd2701f632cb202c3cde39303f1` (507450 B)

These hashes can be deployed as exact-match rules in any multi-scanner or endpoint system that supports SHA-1 (or converted to SHA-256 once the full files are hashed offline).

## 7.4 Combination Logic

High-confidence alerts can be raised by any of the following combinations:

1. DEADD00F rule OR modern type 0x08 hash/size → covers essentially all mature containers (B/C/D)

2. KIEA rule AND (presence of two type 0x09 records) → Generation D dual-driver with very high specificity

3. Type 0x0A 507450 B AND small type 0x08 (≈50–105 KB) → Generation A with high specificity

4. Type 0x0A 50344 B AND type 0x09 AND DEADD00F → Generation C transitional packaging

Because the DEADD00F + SpringBoard pattern is both unique and present in every mature container, it is the single best “first pass” indicator. Everything else can be used for generational attribution or for confirmation.

## 7.5 False-Positive Discussion

- DEADD00F magic alone (without the SpringBoard string or size constraint) is theoretically possible in other contexts; the combination with “SpringBoard” and a tiny file size makes accidental matches extremely unlikely.

- Exact file-size rules for the type 0x08 and type 0x0F modules are safe only when the scanner is looking at discrete extracted modules or when the size is checked in conjunction with Mach-O headers. In a large disk image a random 228928-byte file is possible but statistically uncommon; pairing with the SHA or with Mach-O magic reduces residual risk to near zero.

- KIEA (“KIEA” at offset 0 + exact 24844 bytes) has no known benign collisions.

- The compact 50344-byte type 0x0A dylib is the weakest of the size-only rules and should preferably be combined with the presence of a type 0x09 or DEADD00F record.

## 7.6 Coverage Matrix

| Rule / Indicator | Gen A | Early B | Late B | Gen C | Gen D |
|------------------|-------|---------|--------|-------|-------|
| DEADD00F + SpringBoard | | ✓ | ✓ | ✓ | ✓ |
| Type 0x08 modern (228928) | | | ✓ | ✓* | ✓ |
| Type 0x08 older (196864) | | ✓ | | ✓* | |
| KIEA (24844) | | | | | ✓ |
| Dual f1 0x90000+0x90001 | | | | | ✓ |
| Type 0x0A large (507450) | ✓ | | | | |
| Type 0x0A compact (50344) | | | | ✓ | |

\* One Generation C container uses the older implant/persistence pair.

The matrix shows that a scanner implementing only the DEADD00F rule plus the two type 0x08 size/hash rules already achieves complete coverage of every mature container in the corpus.

## 7.7 Recommended Deployment Order

1. Deploy DEADD00F + SpringBoard rule (highest coverage, lowest complexity).
2. Add exact size or SHA rules for the two type 0x08 implants.
3. Add KIEA rule for Generation D attribution.
4. Add type 0x0A size rules if Generation A or C coverage is required.
5. Optionally parse F00DBEEF containers for the dual-f1 condition when full container context is available.

---

# PRIORITY 4 — FORMAL GENERATION DECISION TREE AND TIMELINE ARGUMENTS

## 6.4 Formal Generation Assignment Decision Tree

The following decision procedure assigns any recovered F00DBEEF container to one of the four generations (or to the anomalous category) using only static fields present in the manifest or recoverable from the entry list.

```
START
  │
  ├─ Contains type 0x05 (KIEA) record?
  │     YES → Generation D (Dual-Driver)
  │             (confirm: two type 0x09 with f1 0x90000 and 0x90001)
  │     NO
  │
  ├─ Contains type 0x09 record?
  │     NO  → Generation A (or Anomalous if no type 0x0A either)
  │     YES
  │
  ├─ Contains type 0x0A record?
  │     YES → Generation C (Transitional)
  │     NO  → Generation B (Classic Single Type-0x09)
  │
  └─ (Optional sub-classification for Gen B)
        type 0x08 size == 228928 → Late B (modern implant)
        type 0x08 size == 196864 → Early B (older implant)
```

This tree is complete for the twenty containers examined; every container falls into exactly one leaf.

## 6.5 Relative Dating Arguments

Absolute calendar dating is not possible from the static corpus alone. Relative order can be established with high confidence:

**Argument 1 — Type 0x0A primacy**  
Generation A containers contain only type 0x0A + small type 0x08. They lack DEADD00F, type 0x09 and type 0x0F. No later generation reverts to this minimal structure. Therefore Generation A is earlier than B/C/D.

**Argument 2 — Introduction of the modern support-layer triple**  
DEADD00F + type 0x09 + type 0x0F appear together for the first time in Generation B and remain present in every subsequent mature container. This triple is therefore a stable “modern” baseline that post-dates Generation A.

**Argument 3 — Implant/persistence coordinated revision**  
Inside Generation B an older type 0x08/0x0F pair and a newer pair coexist. The newer pair is the only pair used by Generation D and by the majority of Generation C. The revision therefore occurred during the life of Generation B and was complete before Generation D.

**Argument 4 — Transitional retention of type 0x0A**  
Generation C carries both a full type 0x09 stack and a compact type 0x0A dylib. This is most economically explained as a packaging strategy that retained an older path while the newer path was already operational. It sits logically between pure single-driver Generation B and the dual-driver design that eliminates type 0x0A.

**Argument 5 — Dual-driver as terminal refinement**  
Generation D introduces a new mechanism (f1 low-bit driver selection + shared external constants) that has no precedent in earlier generations and that eliminates the need for the type 0x0A fallback. Only two containers received this treatment. It is therefore the latest recovered design.

Taken together the five arguments produce the linear relative order:

```
A → B (with internal implant revision) → C → D
```

## 6.6 Design-Pressure Narrative (Expanded)

The single most important engineering insight visible in the corpus is the cost of version coverage under the classic single-driver model.

In Generation B the operators already needed at least seven distinct type 0x09 binaries whose sizes ranged from 231 KB to 333 KB. Each new iOS point release or security patch that changed relevant kernel offsets or PAC gadgets would have required either a new full driver build or invasive binary patching. Packaging and distributing many near-duplicate multi-hundred-kilobyte drivers is operationally expensive and increases the forensic footprint.

The Generation D redesign attacks exactly this cost:

- Two driver variants are shipped instead of many.
- Version-specific data is externalised into a single shared 24 KB KIEA blob.
- Selection is reduced to a single bit test on the f1 field.
- The same KIEA blob can be paired with different driver builds (as the two dual-driver containers demonstrate).

Whether the redesign was motivated by operational security, by engineering convenience, or by both cannot be determined from static evidence alone. The structural effect, however, is unambiguous: the number of full driver builds required for a given coverage window drops sharply.

---

# PRIORITY 6 — METHODOLOGY, LIMITATIONS, REPRODUCIBILITY

## 8.4 Detailed Methodology

### Data Sources
- Repository tree under payloads/ (complete recursive listing)
- payloads/manifest.json (authoritative f1 / type / size / SHA index)
- Previously published dual-driver original research (companion report)
- Direct size and SHA-1 verification of extracted modules

### Analytical Steps Performed
1. Enumeration of every container directory and every entry record.
2. Construction of a presence/absence matrix for types 0x05, 0x07, 0x08, 0x09, 0x0A and 0x0F.
3. Identification of shared SHA-1 identities across containers.
4. Clustering of containers by identical module sets → four generations.
5. Size-distribution analysis of type 0x09 binaries inside Generation B.
6. Formulation of the relative chronology and design-pressure narrative.
7. Derivation of detection rules from the highest-signal shared artifacts.

### Tools Used
- Standard Unix utilities (find, ls, sha1sum equivalents via repository metadata)
- Python for table generation and consistency checks
- Manual cross-referencing of manifest.json against tree listings

No commercial disassembler, emulator, or dynamic analysis system was used. All conclusions are therefore limited to what can be observed from file-level metadata and previously established container/record structures.

## 8.5 Limitations (Expanded)

1. Internal code of the large binaries (type 0x09 drivers, type 0x08 implants, type 0x0A modules) remains unexamined. Size and SHA identity establish similarity and difference but not functional content.

2. The precise layout and semantics of the KIEA constants table beyond the four-byte magic and overall length are unknown. Correlation against XNU headers or against indexing logic inside the drivers would be required.

3. Absolute dating is impossible. Only relative order is supported.

4. The secondary 468-byte type 0x07 records vary across containers; their exact purpose is not recovered.

5. One anomalous container (raw.bin only) is left unclassified.

6. The analysis is scoped to the skilfoy/coruna repository snapshot. Other private or unrecovered containers may exist and could alter the taxonomy.

## 8.6 Reproducibility Checklist

An independent analyst can verify every structural claim in this report by performing the following steps against the public repository:

- [ ] Clone https://github.com/skilfoy/coruna
- [ ] List all directories under payloads/
- [ ] Confirm 20 container directories (including the anomalous raw.bin entry)
- [ ] Parse payloads/manifest.json and extract f1 / type / size / SHA for every entry
- [ ] Verify that exactly two containers contain a type 0x05 record of 24844 bytes
- [ ] Verify that those two containers each contain two type 0x09 records whose f1 values are 0x90000 and 0x90001
- [ ] Verify that the DEADD00F SHA ea2db48a… appears in every container that also contains a type 0x09 record
- [ ] Verify the modern / older type 0x08 size split (228928 vs 196864)
- [ ] Confirm that no container mixes a modern type 0x08 with an older type 0x0F
- [ ] Confirm that type 0x0A is present in Generation A and Generation C only
- [ ] Re-derive the four-generation taxonomy using the decision tree in §6.4

All of the above checks are purely static and can be completed in a few hours.

---

# EXPANDED APPENDICES

## Appendix D — Complete Type 0x09 Size and Identity Register

Every distinct type 0x09 binary recovered in the corpus:

| Size | SHA-1 (prefix) | Generation(s) | Container prefix(es) | Role |
|------|----------------|---------------|----------------------|------|
| 333520 | 603f703d… | D | 377bed74… | Dual primary |
| 333504 | c90bbcb5… | B (early) | 7a1cef00… | Single |
| 330304 | aace9599… | D | 377bed74… | Dual secondary |
| 300912 | a284d84f… | B (late), C | ae7efd66…, 1b2cbbde… | Single / C |
| 300912 | 2a446a3b… | B (early) | 226cbd84… | Single |
| 284048 | 172b89e4… | B, C, D | 38af3c8b…, c8a14d79…, f4120dc6…, 13344176… (primary) | Multiple |
| 284048 | fa7f7a9e… | B (early), C | 38af3c8b…, e9f89858… | Single / C |
| 263536 | 0cfd6098… | D | 13344176… | Dual secondary |
| 249024 | 1f084486… | B (early) | 48000486… | Single |
| 248784 | a1f063dd… | B (late) | a78a9419… | Single |
| 232256 | 2c3b7f3f… | B (early) | 5258f6e3… | Single |
| 231264 | 564da86d… | B (late) | b442ab11… | Single |

Notes: Size 284048 appears in more containers than any other type 0x09 size and crosses generational boundaries (B, C and D). The two dual-driver secondaries (330304 and 263536) are unique to Generation D. No type 0x09 binary smaller than 231 KB appears in any mature container.

## Appendix E — Generation Membership Quick Reference

**Generation D (Dual-Driver)**  
377bed7460f7538f96bbad7bdc2b8294bdc54599  
1334417664270db20af705f422878c53c8378203

**Generation C (Transitional)**  
1b2cbbde08f8b2330b7400abcb97c9573973e942  
c8a14d79a27953242d60243ee2f505a85d9232cc  
e9f898587620186e31119fbf32660f26c1e048e0  
f4120dc6717a489435d86943472c5a2444aac8e6

**Generation B — Older implant cohort**  
226cbd845c5f470075505392be8693ec6d4f5ba3  
38af3c8ba461079a0edc83585023f76843066dcf  
4800048658463f971e752ff93c1767e9ae7f3431  
5258f6e3eef3eda249179aa1122b50b03cbeea18  
7a1cef00016b950be42f5288ead21fa6fccc3107

**Generation B — Newer implant cohort**  
a78a94196b5d2c95865f6a8423a6b8eb86d07c6c  
ae7efd66ecde9e964cfe92f64e9b6461fce38f28  
b442ab113b829ff8c7bf34afa4d2d997889f308f

**Generation A — Dual small type 0x0A**  
2a1d692b7b5ba793527b2c14b48db21a3e5d2c5f  
5e89f83ec50c6223d664d3f3260ef874a3d6d796

**Generation A — Large type 0x0A.bin**  
72a5ac816709f9c331f2b3afb76cd3d96517ea14  
980c77f1747afa9ac1fa5f8fbfb9e6663e9f82bb  
f8a86cf368fdbbe294813926a2a229df041eb758

**Anomalous**  
7a7d99099b035b2c6512b6ebeeea6df1ede70fbb

## Appendix F — f1 Namespace Reference (Complete)

| f1 (hex) | f1 (dec) | Type | Observed Role | Generations |
|----------|----------|------|---------------|-------------|
| 0x50000 | 327680 | 0x05 | KIEA shared constants | D |
| 0x70000 | 458752 | 0x07 | Secondary configuration | B, C, D |
| 0x70005 | 458757 | 0x07 | Primary DEADD00F / SpringBoard config | B, C, D |
| 0x80000 | 524288 | 0x08 | Post-exploitation implant | All |
| 0x90000 | 589824 | 0x09 | Primary (or sole) kernel driver | B, C, D |
| 0x90001 | 589825 | 0x09 | Secondary kernel driver (selectable) | D |
| 0xA0000 | 655360 | 0x0A | Compact type 0x0A dylib | C |
| 0xA0001 | 655361 | 0x0A | Generation A type 0x0A.bin (small) | A |
| 0xA0002 | 655362 | 0x0A | Generation A type 0x0A (dylib or large bin) | A |
| 0xF0000 | 983040 | 0x0F | Persistence / SpringBoard injection | B, C, D |

The regularity of this namespace is itself a detection and classification aid: once an f1 value is observed, the expected type and approximate role of the corresponding record can be predicted with high confidence.

## Appendix G — Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-07-26 | Initial comparative survey and inventory |
| 1.1 | 2026-07-26 | Full Gen D/C tables, Type 0x08/0x0A analysis |
| 1.2 | 2026-07-26 | Complete Generation B entry tables and size analysis |
| 1.3 | 2026-07-27 | Full detection rule set, decision tree, methodology |
| 1.4 | 2026-07-27 | Expanded appendices, type 0x09 register, multi-part publish |

Companion document:  
[DUAL_DRIVER_SUPPORT_LAYER_ORIGINAL_RESEARCH.md](DUAL_DRIVER_SUPPORT_LAYER_ORIGINAL_RESEARCH.md)  
(focused exclusively on the internal design of the Generation D dual-driver and KIEA constants mechanism)

---

**End of complete report.**

The published report (index + four parts) now contains:
- Complete technical inventory of all 20 containers with entry tables
- Full Generation B entry tables and size-clustering analysis
- Expanded Type 0x08 and Type 0x0A comparative sections
- Formal generation decision tree and relative-dating arguments
- Complete detection indicator ranking, YARA rules, hash lists and coverage matrix
- Methodology, limitations and reproducibility checklist
- Extended appendices including the type 0x09 size/identity register
