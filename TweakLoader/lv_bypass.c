#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <sys/syscall.h>

#define ASM(...) __asm__(#__VA_ARGS__)
// ldr x8, value; br x8; value: .ascii "\x41\x42\x43\x44\x45\x46\x47\x48"
static const char patch[] = {0x88,0x00,0x00,0x58,0x00,0x01,0x1f,0xd6,0x1f,0x20,0x03,0xd5,0x1f,0x20,0x03,0xd5,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41};

// Signatures to search for
static const char mmapSig[] = {0xB0, 0x18, 0x80, 0xD2, 0x01, 0x10, 0x00, 0xD4};
static const char fcntlSig[] = {0x90, 0x0B, 0x80, 0xD2, 0x01, 0x10, 0x00, 0xD4};
static const char syscallSig[] = {0x01, 0x10, 0x00, 0xD4};
static int (*orig_fcntl)(int fildes, int cmd, void *param) = 0;

static void (*next_exit)(int);
static int (*_printf)(const char *s, ...);
static int (*_mprotect)(void*, size_t, int);
static int (*_munmap)(void*, size_t);
static void* (*__mmap)(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
static int (*__fcntl)(int fildes, int cmd, void* param);
static void* (*_dlopen)(const char* path, int mode);
const char * (*_dlerror)(void);

static kern_return_t (*_task_info)(task_name_t target_task, task_flavor_t flavor,
                               task_info_t task_info_out,
                               mach_msg_type_number_t *task_info_outCnt);
static mach_port_t _mach_task_self_;

kern_return_t builtin_vm_protect(mach_port_name_t task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_max, vm_prot_t new_prot);
static void init_bypassDyldLibValidation(void);

int dyld_lv_bypass_init(void * (*_dlsym)(void* handle, const char* symbol),
    const char *next_stage_dylib_path)
{
    _printf = _dlsym(RTLD_DEFAULT, "printf");
    if (!_printf)
        return -0x41414141;

    __fcntl = _dlsym(RTLD_DEFAULT, "__fcntl");
    if (!__fcntl)
        return -0x41414142;

    __mmap = _dlsym(RTLD_DEFAULT, "__mmap");
    if (!__mmap)
        return -0x41414143;

    _task_info = _dlsym(RTLD_DEFAULT, "task_info");
    if (!_task_info)
        return -0x41414144;

    mach_port_t *portp = _dlsym(RTLD_DEFAULT, "mach_task_self_");
    if (!portp)
        return -0x41414145;

    _mach_task_self_ = *portp;

    _dlopen = _dlsym(RTLD_DEFAULT, "dlopen");
    if (!_dlopen)
        return -0x41414146;

    _dlerror = _dlsym(RTLD_DEFAULT, "dlerror");
    if (!_dlerror)
        return -0x41414147;

    _munmap = _dlsym(RTLD_DEFAULT, "munmap");
    if (!_dlerror)
        return -0x41414148;

    _mprotect = _dlsym(RTLD_DEFAULT, "mprotect");
    if (!_dlerror)
        return -0x41414149;

    next_exit = _dlsym(RTLD_DEFAULT, "exit");
    if (!next_exit)
        return -0x41414150;

    init_bypassDyldLibValidation();

    _printf("[DyldLVBypass] dlopen %s\n", next_stage_dylib_path);

    void *next_stage = _dlopen(next_stage_dylib_path, RTLD_NOW);
    if (!next_stage) {
        _printf("%s\n", _dlerror());
        return -0x41414160;
    }

    _printf("[DyldLVBypass] dlopen OK\n", next_stage_dylib_path);

    int (*next_stage_main)() = _dlsym(next_stage, "next_stage_main");
    if (!next_stage_main) {
        _printf("%s\n", _dlerror());
        return -0x41414161;
    }

//    _printf("[DyldLVBypass] jumping to next stage\n", next_stage_dylib_path);
//    next_exit(next_stage_main());

    return 0;
}

static int builtin_memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;

    while (n--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }

        ++p1;
        ++p2;
    }

    return 0;
}

static struct dyld_all_image_infos *_alt_dyld_get_all_image_infos(void) {
    static struct dyld_all_image_infos *result;
    if (result) {
        return result;
    }
    struct task_dyld_info dyld_info;
    mach_vm_address_t image_infos;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t ret;
    ret = _task_info(_mach_task_self_,
                    TASK_DYLD_INFO,
                    (task_info_t)&dyld_info,
                    &count);
    if (ret != KERN_SUCCESS) {
        return NULL;
    }
    image_infos = dyld_info.all_image_info_addr;
    result = (struct dyld_all_image_infos *)image_infos;
    return result;
}

// Since we're patching libsystem_kernel, we must avoid calling to its functions
static void builtin_memcpy(char *target, const char *source, size_t size) {
    for (int i = 0; i < size; i++) {
        target[i] = source[i];
    }
}

// Originated from _kernelrpc_mach_vm_protect_trap
ASM(
.global _builtin_vm_protect \n
_builtin_vm_protect:     \n
    mov x16, #-0xe       \n
    svc #0x80            \n
    ret
);

static bool redirectFunction(char *name, void *patchAddr, void *target) {
    kern_return_t kret = builtin_vm_protect(_mach_task_self_, (vm_address_t)patchAddr, sizeof(patch), false, PROT_READ | PROT_WRITE | VM_PROT_COPY);
    if (kret != KERN_SUCCESS) {
        _printf("[DyldLVBypass] vm_protect(RW) fails at line %d\n", __LINE__);
        return FALSE;
    }
    
    builtin_memcpy((char *)patchAddr, patch, sizeof(patch));
#if __arm64e__
    *(void **)((char*)patchAddr + 16) = __builtin_ptrauth_strip(target, 0);
#else
    *(void **)((char*)patchAddr + 16) = target;
#endif
    
    kret = builtin_vm_protect(_mach_task_self_, (vm_address_t)patchAddr, sizeof(patch), false, PROT_READ | PROT_EXEC);
    if (kret != KERN_SUCCESS) {
        _printf("[DyldLVBypass] vm_protect(RX) fails at line %d", __LINE__);
        return FALSE;
    }
    
    _printf("[DyldLVBypass] hook %s(%p) succeed!\n", name, patchAddr);
    return TRUE;
}

static bool searchAndPatch(char *name, char *base, const char *signature, int length, void *target) {
    char *patchAddr = NULL;
    for(int i=0; i < 0x80000; i+=4) {
        if (base[i] == signature[0] && builtin_memcmp(base+i, signature, length) == 0) {
            patchAddr = base + i;
            break;
        }
    }
    
    if (patchAddr == NULL) {
        _printf("[DyldLVBypass] hook %s fails line %d\n", name, __LINE__);
        return FALSE;
    }
    
    _printf("[DyldLVBypass] found %s at %p\n", name, patchAddr);
    return redirectFunction(name, patchAddr, target);
}

static void* hooked_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    void *map = __mmap(addr, len, prot, flags, fd, offset);
    if (map == MAP_FAILED && fd && (prot & PROT_EXEC)) {
        map = __mmap(addr, len, PROT_READ | PROT_WRITE, flags | MAP_PRIVATE | MAP_ANON, 0, 0);
        void *memoryLoadedFile = __mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, offset);
        builtin_memcpy(map, memoryLoadedFile, len);
        _munmap(memoryLoadedFile, len);
        _mprotect(map, len, prot);
    }
    return map;
}

static int hooked___fcntl(int fildes, int cmd, void *param) {
    if (cmd == F_ADDFILESIGS_RETURN) {
#if !(TARGET_OS_MACCATALYST || TARGET_OS_SIMULATOR)
        // attempt to attach code signature on iOS only as the binaries may have been signed
        // on macOS, attaching on unsigned binaries without CS_DEBUGGED will crash
        orig_fcntl(fildes, cmd, param);
#endif
        fsignatures_t *fsig = (fsignatures_t*)param;
        // called to check that cert covers file.. so we'll make it cover everything ;)
        fsig->fs_file_start = 0xFFFFFFFF;
        return 0;
    }

    // Signature sanity check by dyld
    else if (cmd == F_CHECK_LV) {
        orig_fcntl(fildes, cmd, param);
        // Just say everything is fine
        return 0;
    }
    
    // If for another command or file, we pass through
    return orig_fcntl(fildes, cmd, param);
}

static void init_bypassDyldLibValidation(void) {
    _printf("[DyldLVBypass] init\n");
    
    // Modifying exec page during execution may cause SIGBUS, so ignore it now
    // Only comment this out if only one thread (main) is running
    //signal(SIGBUS, SIG_IGN);
    
    orig_fcntl = __fcntl;
    char *dyldBase = (char *)_alt_dyld_get_all_image_infos()->dyldImageLoadAddress;
    //redirectFunction("mmap", mmap, hooked_mmap);
    //redirectFunction("fcntl", fcntl, hooked_fcntl);
    searchAndPatch("dyld_mmap", dyldBase, mmapSig, sizeof(mmapSig), hooked_mmap);
    bool fcntlPatchSuccess = searchAndPatch("dyld_fcntl", dyldBase, fcntlSig, sizeof(fcntlSig), hooked___fcntl);
    
    // dopamine already hooked it, try to find its hook instead
    if(!fcntlPatchSuccess) {
        char* fcntlAddr = 0;
        // search all syscalls and see if the the instruction before it is a branch instruction
        for(int i=0; i < 0x80000; i+=4) {
            if (dyldBase[i] == syscallSig[0] && builtin_memcmp(dyldBase+i, syscallSig, 4) == 0) {
                char* syscallAddr = dyldBase + i;
                uint32_t* prev = (uint32_t*)(syscallAddr - 4);
                if(*prev >> 26 == 0x5) {
                    fcntlAddr = (char*)prev;
                    break;
                }
            }
        }
        
        if(fcntlAddr) {
            uint32_t* inst = (uint32_t*)fcntlAddr;
            int32_t offset = ((int32_t)((*inst)<<6))>>4;
            _printf("[DyldLVBypass] Dopamine hook offset = %x\n", offset);
            orig_fcntl = (void*)((char*)fcntlAddr + offset);
            redirectFunction("dyld_fcntl (Dopamine)", fcntlAddr, hooked___fcntl);
        } else {
            _printf("[DyldLVBypass] Dopamine hook not found\n");
        }
    }
}
