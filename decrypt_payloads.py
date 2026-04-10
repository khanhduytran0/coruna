#!/usr/bin/env python3
"""
Coruna Payload Decryption Pipeline

Implements the full decryption chain described in ANALYSIS.md:
  1. Derive master ChaCha20 key from fqMaGkN4() uint32 array
  2. Decrypt manifest with ChaCha20-DJB (nonce=0)
  3. LZMA decompress (check 0x0BEDF00D header)
  4. Parse manifest entries (19 × 0x64 bytes) to extract per-file keys
  5. Decrypt each payload file with its per-file key
  6. LZMA decompress each payload
  7. Parse F00DBEEF containers and extract Mach-O dylibs / data blobs
"""

import struct
import lzma
import os
import sys
import json
import hashlib

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOADED_DIR = os.path.join(BASE_DIR, "downloaded")
OUTPUT_DIR = os.path.join(BASE_DIR, "payloads_decrypted")

# Master key uint32 array from group.html (original, pre-modification):
#   fqMaGkN4([3436285875, 2332907478, 2884495420, 233193687,
#             1144711575, 1605576699, 1942246444, 1994816675])
MASTER_KEY_UINT32 = [
    3436285875, 2332907478, 2884495420, 233193687,
    1144711575, 1605576699, 1942246444, 1994816675,
]

# Manifest filename (also the first file fetched from C2)
MANIFEST_HASH = "7a7d99099b035b2c6512b6ebeeea6df1ede70fbb"

# Segment type descriptions
SEGMENT_TYPES = {
    0x05: ("data", "bin",  "Kernel offsets/gadgets"),
    0x07: ("data", "bin",  "Config/metadata"),
    0x08: ("dylib", "dylib", "Main implant (powerd target)"),
    0x09: ("dylib", "dylib", "Kernel/sandbox escape"),
    0x0a: ("mixed", None,  "Additional exploit module"),
    0x0f: ("dylib", "dylib", "Persistence (launchd/powerd hook)"),
}

# Manifest flags → iOS target mapping
FLAGS_MAP = {
    0xf230: "iOS 15.x arm64",
    0xf330: "iOS 15.x arm64e",
    0xf240: "iOS 16.0-16.2 arm64",
    0xf340: "iOS 16.0-16.2 arm64e",
    0xf270: "iOS 16.6-17.0 arm64",
    0xf370: "iOS 16.6-17.0 arm64e",
    0xf280: "iOS 16.3-16.5 arm64",
    0xf380: "iOS 16.3-16.5 arm64e",
    0xf290: "iOS 17.0-17.2 arm64",
    0xf390: "iOS 17.0-17.2 arm64e",
    0xf275: "Extended arm64",
    0xf375: "Extended arm64e",
    0xf373: "Extended arm64e (v2)",
    0xf383: "Extended arm64e (v3)",
    0xa205: "Older/special arm64",
    0xa305: "Older/special arm64e",
    0xa306: "Older/special arm64e (v2)",
    0xa303: "Older/special arm64",
    0xa304: "Older/special arm64 (v2)",
}


# ---------------------------------------------------------------------------
# Step 1: Key derivation — fqMaGkN4()
# ---------------------------------------------------------------------------

def fqMaGkN4(arr):
    """
    Reproduce the fqMaGkN4() function from group.html.
    Converts uint32 array → JS string (2 UTF-16 chars per word).
    Returns raw bytes in UTF-16LE encoding (= the ChaCha20 key).
    """
    chars = []
    for q in arr:
        b0 = q & 0xFF
        b1 = (q >> 8) & 0xFF
        b2 = (q >> 16) & 0xFF
        b3 = (q >> 24) & 0xFF
        chars.append((b1 << 8) | b0)
        chars.append((b3 << 8) | b2)
    # Convert to UTF-16LE bytes (each char → 2 bytes, little-endian)
    key_bytes = b""
    for c in chars:
        key_bytes += struct.pack("<H", c)
    return key_bytes


def derive_master_key():
    """Derive the 32-byte master ChaCha20 key."""
    key = fqMaGkN4(MASTER_KEY_UINT32)
    assert len(key) == 32, f"Expected 32-byte key, got {len(key)}"
    return key


# ---------------------------------------------------------------------------
# Step 2: ChaCha20-DJB implementation
# ---------------------------------------------------------------------------

def _rotl32(v, n):
    """32-bit left rotation."""
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _quarter_round(state, a, b, c, d):
    """ChaCha20 quarter round."""
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 7)


def _chacha20_block(key, counter, nonce):
    """
    Generate one 64-byte ChaCha20 keystream block.

    DJB variant:
      - 4 words: sigma constant ("expand 32-byte k")
      - 8 words: key (32 bytes)
      - 2 words: counter (64-bit, little-endian)
      - 2 words: nonce (64-bit, little-endian)
    """
    # "expand 32-byte k" as 4 little-endian uint32
    sigma = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    # Key: 8 × uint32 LE
    k = list(struct.unpack("<8I", key))

    # Counter: 64-bit LE → 2 words
    ctr = [counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF]

    # Nonce: 64-bit LE → 2 words
    n = [nonce & 0xFFFFFFFF, (nonce >> 32) & 0xFFFFFFFF]

    state = sigma + k + ctr + n
    working = list(state)

    # 20 rounds (10 double-rounds)
    for _ in range(10):
        # Column rounds
        _quarter_round(working, 0, 4,  8, 12)
        _quarter_round(working, 1, 5,  9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        # Diagonal rounds
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7,  8, 13)
        _quarter_round(working, 3, 4,  9, 14)

    # Add original state
    output = []
    for i in range(16):
        output.append((working[i] + state[i]) & 0xFFFFFFFF)

    return struct.pack("<16I", *output)


def chacha20_decrypt(key, data, nonce=0):
    """
    Decrypt data using ChaCha20-DJB.
    64-bit counter starting at 0, 64-bit nonce (default all zeros).
    """
    result = bytearray()
    num_blocks = (len(data) + 63) // 64

    for block_idx in range(num_blocks):
        keystream = _chacha20_block(key, block_idx, nonce)
        offset = block_idx * 64
        chunk = data[offset:offset + 64]
        for i in range(len(chunk)):
            result.append(chunk[i] ^ keystream[i])

    return bytes(result)


# ---------------------------------------------------------------------------
# Step 3: LZMA decompression
# ---------------------------------------------------------------------------

def lzma_decompress(data):
    """
    Decompress data with 0x0BEDF00D header.
    Header: 4 bytes magic + 4 bytes decompressed size, followed by XZ stream.
    """
    if len(data) < 8:
        raise ValueError(f"Data too short for LZMA header: {len(data)} bytes")

    magic = struct.unpack("<I", data[:4])[0]
    if magic != 0x0BEDF00D:
        raise ValueError(f"Bad LZMA magic: 0x{magic:08x} (expected 0x0BEDF00D)")

    expected_size = struct.unpack("<I", data[4:8])[0]
    compressed = data[8:]

    # Try XZ format first (fd 37 7a 58 5a 00)
    if compressed[:6] == b'\xfd7zXZ\x00':
        decompressed = lzma.decompress(compressed)
    else:
        # Try raw LZMA
        decompressed = lzma.decompress(compressed, format=lzma.FORMAT_ALONE)

    if len(decompressed) != expected_size:
        print(f"  WARNING: Decompressed size {len(decompressed)} != expected {expected_size}")

    return decompressed


# ---------------------------------------------------------------------------
# Step 4: F00DBEEF container parser
# ---------------------------------------------------------------------------

def parse_f00dbeef(data):
    """
    Parse a F00DBEEF container.
    Returns list of (type, entry_data) tuples.
    """
    if len(data) < 8:
        raise ValueError(f"Data too short for F00DBEEF: {len(data)} bytes")

    magic = struct.unpack("<I", data[:4])[0]
    if magic != 0xF00DBEEF:
        raise ValueError(f"Bad F00DBEEF magic: 0x{magic:08x}")

    entry_count = struct.unpack("<I", data[4:8])[0]
    entries = []

    for i in range(entry_count):
        off = 8 + i * 16
        f1, f2, data_offset, data_size = struct.unpack("<4I", data[off:off + 16])
        seg_type = (f1 >> 16) & 0xFFFF
        entry_data = data[data_offset:data_offset + data_size]
        entries.append({
            "index": i,
            "type": seg_type,
            "f1": f1,
            "f2": f2,
            "offset": data_offset,
            "size": data_size,
            "data": entry_data,
        })

    return entries


# ---------------------------------------------------------------------------
# Step 5: Manifest parser
# ---------------------------------------------------------------------------

def parse_manifest(data):
    """
    Parse the decrypted manifest (2192 bytes, 19 entries × 0x64 bytes).
    Each entry at offset 0x120 + i*0x64:
      +0x00: 6 bytes header/padding
      +0x06: 2 bytes flags (iOS version / arch)
      +0x08: 32 bytes per-file ChaCha20 key
      +0x28: 48 bytes filename (40-char hex hash + ".min.js" + NUL)
    """
    # The manifest is a F00DBEEF container; the raw data inside contains the entries
    # But per ANALYSIS.md, the manifest itself is 2192 bytes with entries starting
    # at a specific offset. Let's find the entry table.

    entries = []
    # Try to find entries - they should start after some header
    # ANALYSIS.md says 19 entries at offset 0x120, each 0x64 (100) bytes
    # But let's also handle if the offset is different

    # First check if this is a raw manifest or inside F00DBEEF
    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0xF00DBEEF:
        # It's a container - the manifest entries are the payload data
        container_entries = parse_f00dbeef(data)
        if container_entries:
            manifest_data = container_entries[0]["data"]
        else:
            manifest_data = data
    else:
        manifest_data = data

    # Scan for entries - look for the pattern where filenames appear
    # Each entry is 0x64 bytes. Filenames are 40-char hex hashes + ".min.js"
    entry_size = 0x64  # 100 bytes

    # Try to find the start offset by scanning for known hash patterns
    start_offset = None
    for test_offset in range(0, min(len(data) - entry_size, 0x200)):
        # Check if bytes at test_offset+0x28 look like a hex hash filename
        fname_bytes = data[test_offset + 0x28:test_offset + 0x28 + 48]
        try:
            fname = fname_bytes.split(b'\x00')[0].decode('ascii')
            if len(fname) > 40 and fname.endswith('.min.js') and all(c in '0123456789abcdef.' for c in fname.replace('.min.js', '')):
                start_offset = test_offset
                break
        except (UnicodeDecodeError, IndexError):
            continue

    if start_offset is None:
        print("  WARNING: Could not auto-detect manifest entry offset, trying 0x00")
        start_offset = 0

    print(f"  Manifest entry table starts at offset 0x{start_offset:04x}")

    # Parse entries
    i = 0
    offset = start_offset
    while offset + entry_size <= len(data):
        entry_data = data[offset:offset + entry_size]

        # Flags at +0x06
        flags = struct.unpack("<H", entry_data[0x06:0x08])[0]

        # Per-file key at +0x08 (32 bytes)
        per_file_key = entry_data[0x08:0x28]

        # Filename at +0x28 (48 bytes, NUL-terminated)
        fname_raw = entry_data[0x28:0x58]
        try:
            filename = fname_raw.split(b'\x00')[0].decode('ascii')
        except UnicodeDecodeError:
            filename = fname_raw.hex()

        if not filename or not filename.endswith('.min.js'):
            # Might have hit end of entries or padding
            if i > 0:
                break
            offset += entry_size
            continue

        # Extract hash from filename
        file_hash = filename.replace('.min.js', '')

        target = FLAGS_MAP.get(flags, f"Unknown (0x{flags:04x})")

        entries.append({
            "index": i,
            "flags": flags,
            "key": per_file_key,
            "filename": filename,
            "hash": file_hash,
            "target": target,
        })

        i += 1
        offset += entry_size

    return entries


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("Coruna Payload Decryption Pipeline")
    print("=" * 70)

    # --- Step 1: Derive master key ---
    print("\n[Step 1] Deriving master ChaCha20 key from fqMaGkN4()...")
    master_key = derive_master_key()
    print(f"  Master key: {master_key.hex()}")

    expected_key = "b38fd1ccd6570d8b3ce8edabd740e60d97e93a44fb27b35f2c54c473a37ce676"
    if master_key.hex() == expected_key:
        print("  KEY VERIFIED OK")
    else:
        print(f"  WARNING: Key mismatch! Expected {expected_key}")

    # --- Step 2: Load and decrypt manifest ---
    print(f"\n[Step 2] Decrypting manifest ({MANIFEST_HASH})...")

    # Try extracted/ first (base64-decoded), then downloaded/
    manifest_path = os.path.join(BASE_DIR, "extracted", f"{MANIFEST_HASH}.bin")
    if not os.path.exists(manifest_path):
        manifest_path = os.path.join(DOWNLOADED_DIR, f"{MANIFEST_HASH}.min.js")

    if not os.path.exists(manifest_path):
        print(f"  ERROR: Manifest file not found!")
        print(f"  Looked in: extracted/{MANIFEST_HASH}.bin")
        print(f"          and downloaded/{MANIFEST_HASH}.min.js")
        sys.exit(1)

    encrypted_manifest = open(manifest_path, "rb").read()
    print(f"  Encrypted manifest: {len(encrypted_manifest)} bytes")

    decrypted_manifest = chacha20_decrypt(master_key, encrypted_manifest)
    print(f"  After ChaCha20: {len(decrypted_manifest)} bytes")
    print(f"  First 4 bytes: 0x{struct.unpack('<I', decrypted_manifest[:4])[0]:08x}")

    # Check for LZMA header
    lzma_magic = struct.unpack("<I", decrypted_manifest[:4])[0]
    if lzma_magic == 0x0BEDF00D:
        print("  Found 0x0BEDF00D LZMA header — decompressing...")
        manifest_data = lzma_decompress(decrypted_manifest)
        print(f"  Decompressed: {len(manifest_data)} bytes")
    else:
        manifest_data = decrypted_manifest
        print("  No LZMA header found, using raw decrypted data")

    # Check for F00DBEEF
    beef_magic = struct.unpack("<I", manifest_data[:4])[0]
    print(f"  Container magic: 0x{beef_magic:08x}", end="")
    if beef_magic == 0xF00DBEEF:
        print(" (F00DBEEF container)")
    else:
        print(" (unknown)")

    # --- Step 3: Parse manifest entries ---
    print(f"\n[Step 3] Parsing manifest entries...")
    manifest_entries = parse_manifest(manifest_data)
    print(f"  Found {len(manifest_entries)} payload entries")
    print()

    # Print entry table
    print(f"  {'#':>2}  {'Flags':>6}  {'Hash':<42}  {'Target'}")
    print(f"  {'—'*2}  {'—'*6}  {'—'*42}  {'—'*30}")
    for e in manifest_entries:
        print(f"  {e['index']:>2}  0x{e['flags']:04x}  {e['hash']:<42}  {e['target']}")

    # --- Step 4–6: Decrypt each payload ---
    print(f"\n[Step 4-6] Decrypting and extracting payloads...")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    results = {}
    for entry in manifest_entries:
        h = entry["hash"]
        key = entry["key"]
        print(f"\n  --- Payload: {h} ---")
        print(f"  Target: {entry['target']}")
        print(f"  Key: {key.hex()}")

        # Find the encrypted file
        payload_path = os.path.join(DOWNLOADED_DIR, f"{h}.min.js")
        if not os.path.exists(payload_path):
            # Check extracted/
            payload_path = os.path.join(BASE_DIR, "extracted", f"{h}.bin")

        if not os.path.exists(payload_path):
            print(f"  SKIPPED: Encrypted file not found")
            continue

        encrypted = open(payload_path, "rb").read()
        print(f"  Encrypted: {len(encrypted)} bytes")

        # Decrypt with per-file key
        decrypted = chacha20_decrypt(key, encrypted)
        print(f"  After ChaCha20: {len(decrypted)} bytes")

        # Check for LZMA
        if len(decrypted) >= 4:
            dec_magic = struct.unpack("<I", decrypted[:4])[0]
            if dec_magic == 0x0BEDF00D:
                print("  Found 0x0BEDF00D — LZMA decompressing...")
                try:
                    decompressed = lzma_decompress(decrypted)
                    print(f"  Decompressed: {len(decompressed)} bytes")
                except Exception as ex:
                    print(f"  LZMA ERROR: {ex}")
                    continue
            else:
                print(f"  First 4 bytes: 0x{dec_magic:08x} (no LZMA header)")
                decompressed = decrypted
        else:
            decompressed = decrypted

        # Parse F00DBEEF container
        if len(decompressed) >= 4:
            container_magic = struct.unpack("<I", decompressed[:4])[0]
            if container_magic == 0xF00DBEEF:
                print("  Parsing F00DBEEF container...")
                try:
                    container_entries = parse_f00dbeef(decompressed)
                except Exception as ex:
                    print(f"  F00DBEEF PARSE ERROR: {ex}")
                    continue

                print(f"  Found {len(container_entries)} entries:")

                # Create output directory
                out_dir = os.path.join(OUTPUT_DIR, h)
                os.makedirs(out_dir, exist_ok=True)

                entry_results = []
                for ce in container_entries:
                    seg_type = ce["type"]
                    type_info = SEGMENT_TYPES.get(seg_type, ("unknown", "bin", f"Type 0x{seg_type:02x}"))
                    desc = type_info[2]

                    # Determine extension based on content
                    ext = type_info[1]
                    if ext is None:
                        # Check if it's a Mach-O
                        if len(ce["data"]) >= 4:
                            mach_magic = struct.unpack("<I", ce["data"][:4])[0]
                            if mach_magic in (0xFEEDFACE, 0xFEEDFACF, 0xCAFEBABE, 0xBEBAFECA):
                                ext = "dylib"
                            else:
                                ext = "bin"
                        else:
                            ext = "bin"

                    filename = f"entry{ce['index']}_type0x{seg_type:02x}.{ext}"
                    filepath = os.path.join(out_dir, filename)

                    with open(filepath, "wb") as f:
                        f.write(ce["data"])

                    # Check if Mach-O
                    is_macho = False
                    if len(ce["data"]) >= 4:
                        m = struct.unpack("<I", ce["data"][:4])[0]
                        is_macho = m in (0xFEEDFACE, 0xFEEDFACF, 0xCAFEBABE, 0xBEBAFECA)

                    marker = "Mach-O" if is_macho else "data"
                    print(f"    [{ce['index']}] type=0x{seg_type:02x} size={ce['size']:>7}  {marker:>6}  {desc}")

                    entry_results.append({
                        "file": filename,
                        "f1": ce["f1"],
                        "f2": ce["f2"],
                        "type": seg_type,
                        "size": ce["size"],
                    })

                results[h] = entry_results

                # Save raw container too
                raw_path = os.path.join(OUTPUT_DIR, f"{h}.bin")
                with open(raw_path, "wb") as f:
                    f.write(decompressed)

            else:
                print(f"  Not a F00DBEEF container (magic: 0x{container_magic:08x})")
                # Save raw decrypted data
                raw_path = os.path.join(OUTPUT_DIR, f"{h}.bin")
                with open(raw_path, "wb") as f:
                    f.write(decompressed)

    # Save manifest.json
    manifest_json_path = os.path.join(OUTPUT_DIR, "manifest.json")
    with open(manifest_json_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Wrote manifest to {manifest_json_path}")

    # --- Summary ---
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Manifest entries: {len(manifest_entries)}")
    print(f"  Successfully decrypted: {len(results)}")
    print(f"  Output directory: {OUTPUT_DIR}")

    total_dylibs = sum(
        1 for entries in results.values()
        for e in entries
        if e["file"].endswith(".dylib")
    )
    total_bins = sum(
        1 for entries in results.values()
        for e in entries
        if e["file"].endswith(".bin")
    )
    print(f"  Total Mach-O dylibs extracted: {total_dylibs}")
    print(f"  Total data blobs extracted: {total_bins}")
    print(f"  Total files: {total_dylibs + total_bins}")

    # --- Verify against existing payloads/ ---
    existing_dir = os.path.join(BASE_DIR, "payloads")
    if os.path.exists(existing_dir):
        print(f"\n[Verification] Comparing against existing payloads/...")
        match_count = 0
        mismatch_count = 0
        missing_count = 0

        for h, entries in results.items():
            existing_hash_dir = os.path.join(existing_dir, h)
            if not os.path.isdir(existing_hash_dir):
                missing_count += 1
                continue

            for e in entries:
                existing_file = os.path.join(existing_hash_dir, e["file"])
                new_file = os.path.join(OUTPUT_DIR, h, e["file"])

                if not os.path.exists(existing_file):
                    missing_count += 1
                    continue

                existing_data = open(existing_file, "rb").read()
                new_data = open(new_file, "rb").read()

                if existing_data == new_data:
                    match_count += 1
                else:
                    mismatch_count += 1
                    print(f"  MISMATCH: {h}/{e['file']}")
                    print(f"    Existing: {len(existing_data)} bytes")
                    print(f"    New:      {len(new_data)} bytes")

        print(f"  Matched: {match_count}")
        print(f"  Mismatched: {mismatch_count}")
        print(f"  Missing (no reference): {missing_count}")

        if mismatch_count == 0:
            print("  ALL VERIFIED OK")
        else:
            print(f"  WARNING: {mismatch_count} mismatches found!")

    print()


if __name__ == "__main__":
    main()
