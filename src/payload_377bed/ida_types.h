/*
 * ida_types.h — IDA/Hex-Rays type compatibility for clang ARM64
 */
#ifndef IDA_TYPES_H
#define IDA_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <pthread.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
/* mach_vm.h is not available on iOS SDK — declare manually */
#define mach_vm_address_t vm_address_t
#define mach_vm_size_t    vm_size_t
#define mach_vm_offset_t  vm_offset_t
extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);
extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_protect(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);
extern kern_return_t mach_vm_machine_attribute(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_machine_attribute_t, vm_machine_attribute_val_t *);
extern kern_return_t mach_vm_page_info(vm_map_t, mach_vm_address_t, vm_page_info_flavor_t, vm_page_info_t, mach_msg_type_number_t *);
#include <mach/thread_act.h>
#include <mach/host_priv.h>
#include <mach/vm_map.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <spawn.h>
#include <signal.h>
#include <arm_neon.h>

/* ---- IDA integer types ---- */
#define __int8  char
#define __int16 short
#define __int32 int
#define __int64 long long

typedef uint8_t   _UNKNOWN;
typedef union { __int128 o; uint64_t n128_u64[2]; double n128_f64[2]; } __n128;
typedef __int128  xmmword;
typedef char      kernel_version_t[512];
typedef mach_port_t io_master_t;
typedef struct _opaque_pthread_t _opaque_pthread_t;

/* ---- IDA calling conventions (no-ops) ---- */
#define __fastcall
#define __cdecl
#define __usercall
#define __thiscall

/* ---- IDA accessor macros ---- */
#define LODWORD(x)  (*(uint32_t*)&(x))
#define HIDWORD(x)  (*((uint32_t*)&(x) + 1))
#define LOBYTE(x)   (*(uint8_t*)&(x))
#define HIBYTE(x)   (*((uint8_t*)&(x) + sizeof(x) - 1))
#define LOWORD(x)   (*(uint16_t*)&(x))
#define HIWORD(x)   (*((uint16_t*)&(x) + 1))
#define BYTE1(x)    (*((uint8_t*)&(x) + 1))
#define BYTE2(x)    (*((uint8_t*)&(x) + 2))
#define BYTE3(x)    (*((uint8_t*)&(x) + 3))
#define BYTE4(x)    (*((uint8_t*)&(x) + 4))
#define BYTE5(x)    (*((uint8_t*)&(x) + 5))
#define BYTE6(x)    (*((uint8_t*)&(x) + 6))
#define BYTE7(x)    (*((uint8_t*)&(x) + 7))
#define SHIDWORD(x) (*((int32_t*)&(x) + 1))
#define SLOBYTE(x)  (*(int8_t*)&(x))
#define SHIWORD(x)  (*((int16_t*)&(x) + 1))
#define DWORD1(x)   (*((uint32_t*)&(x) + 1))
#define DWORD2(x)   (*((uint32_t*)&(x) + 2))
#define __PAIR64__(h, l) (((uint64_t)(h) << 32) | (uint32_t)(l))
#define __PAIR32__(h, l) (((uint32_t)(h) << 16) | (uint16_t)(l))
#define IDA_INT128_C(h, l) (((__int128)(uint64_t)(h) << 64) | (uint64_t)(l))
#define __CFADD__(a, b)  ((uint64_t)(a) > (uint64_t)(-1) - (uint64_t)(b))
#define __OFSUB__(a, b)  (((a) ^ (b)) < 0 && ((a) ^ ((a) - (b))) < 0)
#define __OFADD__(a, b)  (((a) ^ (b)) >= 0 && ((a) ^ ((a) + (b))) < 0)

/* ---- ARM64 intrinsics ---- */
#define __dsb(x) __asm__ volatile("dsb " #x ::: "memory")
#define __isb(x) __asm__ volatile("isb " #x ::: "memory")
#define __dmb(x) __asm__ volatile("dmb " #x ::: "memory")

/* ---- IDA helpers ---- */
#define __break(x)       __builtin_trap()
#define bswap32(x)       __builtin_bswap32(x)
extern __int64 __chkstk_darwin();
#define MEMORY ((volatile uint64_t *)0)

typedef unsigned int atomic_uint;
typedef unsigned short atomic_ushort;
typedef unsigned char atomic_uchar;
#define atomic_load(p) __atomic_load_n((p), __ATOMIC_SEQ_CST)
#define atomic_store(v, p) __atomic_store_n((p), (__typeof__(*(p)))(v), __ATOMIC_RELEASE)
#define atomic_fetch_add(p, v) __atomic_fetch_add((p), (__typeof__(*(p)))(v), __ATOMIC_ACQ_REL)
#define atomic_exchange(p, v) __atomic_exchange_n((p), (__typeof__(*(p)))(v), __ATOMIC_ACQ_REL)

/* ---- NEON vector unions (IDA uses .i8[n] / .u8[n] member access) ---- */

/* ---- Mach type aliases ---- */
#ifndef host_t
typedef mach_port_t host_t;
#endif

/* ---- SDK compatibility ---- */
/* kIOMasterPortDefault was renamed to kIOMainPortDefault in iOS 15.
   Use 0 (MACH_PORT_NULL) which works for both old and new SDKs. */
#undef kIOMasterPortDefault
#define kIOMasterPortDefault 0
#ifndef SANDBOX_CHECK_NO_REPORT
#define SANDBOX_CHECK_NO_REPORT 0x0001
#endif

/* ---- Private syscalls ---- */
static inline mach_timespec_t ida_mach_timespec(uint64_t x) {
    mach_timespec_t t;
    t.tv_sec = (unsigned int)(x & 0x7FFFFFFFFULL);
    t.tv_nsec = (clock_res_t)((x >> 35) & 0x1FFFFFFFULL);
    return t;
}
#define IDA_MACH_TIMESPEC(x) ida_mach_timespec((uint64_t)(x))
int open_dprotected_np(const char *, int, int, int, ...);
int fileport_makeport(int fd, mach_port_t *port);
int fileport_makefd(mach_port_t port);

/* ---- Data constants (zero-init, fill from binary .rodata) ---- */
/* Declared as extern in .c file, defined there too */


/* Additional compatibility — appended */
#include <sys/utsname.h>
#include <mach-o/loader.h>

#define qmemcpy(d,s,n) memcpy(d,s,n)
#define bswap64(x) __builtin_bswap64(x)
#define __PAIR128__(h,l) (((__int128)(h) << 64) | (uint64_t)(l))
#define WORD6(x) (*((uint16_t*)&(x) + 6))
#define BYTE8(x) (*((uint8_t*)&(x) + 8))
#define BYTE13(x) (*((uint8_t*)&(x) + 13))
/* _ReadStatusReg / ARM64_SYSREG: IDA uses these for mrs instructions.
   ARM64_SYSREG encodes the system register as an integer, and _ReadStatusReg
   reads it. We use the "mrs %0, S<reg>" syntax which accepts numeric encoding. */
#define ARM64_SYSREG(op0,op1,crn,crm,op2) \
    (((op0)<<14)|((op1)<<11)|((crn)<<7)|((crm)<<3)|(op2))
static __attribute__((always_inline)) uint64_t _ReadStatusReg(uint32_t reg) {
    uint64_t val;
    /* Common registers used by the exploit */
    if (reg == ARM64_SYSREG(3,3,13,0,3))      /* tpidrro_el0 */
        __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(val));
    else if (reg == ARM64_SYSREG(3,3,13,0,2))  /* tpidr_el0 */
        __asm__ volatile("mrs %0, tpidr_el0" : "=r"(val));
    else
        val = 0;
    return val;
}

/* IDA uses __semwait_signal, __memcpy_chk etc. as direct calls */

/* struct tags C requires */
typedef struct IONotificationPort IONotificationPort;

/* dyld globals */
extern double dyldVersionNumber;

/* _os_alloc_once */
extern uint64_t _os_alloc_once_table[];

extern kern_return_t ida_import_IOConnectTrap4(
    io_connect_t connect,
    uint32_t index,
    uintptr_t p1,
    uintptr_t p2,
    uintptr_t p3,
    uintptr_t p4) __asm("_IOConnectTrap4");
extern kern_return_t ida_import_IOConnectTrap6(
    io_connect_t connect,
    uint32_t index,
    uintptr_t p1,
    uintptr_t p2,
    uintptr_t p3,
    uintptr_t p4,
    uintptr_t p5,
    uintptr_t p6) __asm("_IOConnectTrap6");
#define IOConnectTrap4 ida_import_IOConnectTrap4
#define IOConnectTrap6 ida_import_IOConnectTrap6

/* NEON union additions for i16/i32/i64/u32/u64 access */
typedef union { int8_t i8[16]; uint8_t u8[16]; int16_t i16[8]; int32_t i32[4]; int64_t i64[2]; uint32_t u32[4]; uint64_t u64[2]; uint64_t q; __int128 o; int8x16_t v; int64x2_t v64; } ida_int8x16_t;
typedef union { int8_t i8[8]; uint8_t u8[8]; int16_t i16[4]; int32_t i32[2]; uint32_t u32[2]; uint64_t q; uint8x8_t v; int8x8_t vs; int32x2_t v32; } ida_uint8x8_t;


/* Additional NEON union types for IDA decompiler output */
typedef union { int8_t i8[8]; uint8_t u8[8]; int16_t i16[4]; int32_t i32[2]; uint32_t u32[2]; uint64_t u64[1]; int64_t i64[1]; uint64_t q; int8x8_t vs; } ida_int8x8_t;
typedef union { int32_t i32[2]; uint32_t u32[2]; int64_t i64[1]; uint64_t u64[1]; uint64_t q; int32x2_t v; } ida_int32x2_t;
typedef union { int64_t i64[2]; uint64_t u64[2]; int32_t i32[4]; uint32_t u32[4]; int16_t i16[8]; int8_t i8[16]; uint8_t u8[16]; __int128 o; int64x2_t v64; int8x16_t v; } ida_int64x2_t;

static inline ida_uint8x8_t ida_vcnt_s8(ida_int8x8_t x) {
    ida_uint8x8_t r;
    r.v = vcnt_s8(x.vs);
    return r;
}
static inline uint16_t ida_vaddlv_u8(ida_uint8x8_t x) {
    return vaddlv_u8(x.v);
}
static inline ida_int64x2_t ida_vaddq_s64(ida_int64x2_t a, ida_int64x2_t b) {
    ida_int64x2_t r;
    r.v64 = vaddq_s64(a.v64, b.v64);
    return r;
}
static inline ida_int32x2_t ida_vrev64_s32(ida_int32x2_t x) {
    ida_int32x2_t r;
    r.v = vrev64_s32(x.v);
    return r;
}
static inline ida_int32x2_t ida_vdup_n_s32(int32_t x) {
    ida_int32x2_t r;
    r.v = vdup_n_s32(x);
    return r;
}
static inline ida_int64x2_t ida_vdupq_n_s64(int64_t x) {
    ida_int64x2_t r;
    r.v64 = vdupq_n_s64(x);
    return r;
}
static inline ida_int8x16_t ida_vbslq_s8(ida_int8x16_t mask, ida_int8x16_t a, ida_int8x16_t b) {
    ida_int8x16_t r;
    r.v = vbslq_s8(mask.v, a.v, b.v);
    return r;
}
static inline ida_int8x16_t ida_vextq_s8(ida_int8x16_t a, ida_int8x16_t b, int n) {
    ida_int8x16_t r;
    (void)n;
    r.v = vextq_s8(a.v, b.v, 8);
    return r;
}
static inline ida_int8x16_t ida_vdupq_n_s8(int8_t x) {
    ida_int8x16_t r;
    r.v = vdupq_n_s8(x);
    return r;
}
#define int8x16_t ida_int8x16_t
#define int8x8_t ida_int8x8_t
#define uint8x8_t ida_uint8x8_t
#define int32x2_t ida_int32x2_t
#define int64x2_t ida_int64x2_t
#define vcnt_s8 ida_vcnt_s8
#define vaddlv_u8 ida_vaddlv_u8
#define vaddq_s64 ida_vaddq_s64
#define vrev64_s32 ida_vrev64_s32
#define vdup_n_s32 ida_vdup_n_s32
#define vdupq_n_s64 ida_vdupq_n_s64
#define vdupq_n_s8 ida_vdupq_n_s8
#define vbslq_s8 ida_vbslq_s8
#define vextq_s8 ida_vextq_s8
#endif /* IDA_TYPES_H */
