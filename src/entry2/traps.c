/*
 * traps.c - Raw Mach trap syscall wrappers
 *
 * Decompiled from entry2_type0x0f.dylib offsets 0x6000–0x60a0
 *
 * These bypass libSystem entirely, issuing svc #0x80 directly.
 * This is done to avoid symbol resolution / interposition and to
 * work in contexts where libSystem may not be fully initialized
 * (e.g., inside a freshly-injected remote thread).
 */

#include "entry2.h"

/* ── 0x6000: BSD syscall 360 — guarded_open_dprotected_np ─────────── *
 * Opens a file with data-protection class, guarded by a guard value.
 *
 * svc #0x80 with x16 = 0x168 (360)
 */
int64_t e2_trap_guarded_open(uint64_t guard, uint64_t path,
                             uint64_t guardflags, uint64_t flags)
{
    register uint64_t x0 __asm__("x0") = guard;
    register uint64_t x1 __asm__("x1") = path;
    register uint64_t x2 __asm__("x2") = guardflags;
    register uint64_t x3 __asm__("x3") = flags;
    register uint64_t x16 __asm__("x16") = 0x168;

    __asm__ volatile(
        "svc #0x80\n"
        "mov x1, xzr\n"
        "b.lo 1f\n"
        "mov x1, x0\n"
        "mov x0, #-1\n"
        "1:\n"
        : "+r"(x0), "+r"(x1)
        : "r"(x2), "r"(x3), "r"(x16)
        : "memory", "cc"
    );
    return (int64_t)x0;
}

/* ── 0x601c: BSD syscall 361 — guarded_write_np ──────────────────── *
 *
 * svc #0x80 with x16 = 0x169 (361)
 */
int64_t e2_trap_guarded_write(uint64_t guard, uint64_t fd,
                              uint64_t buf, uint64_t nbyte)
{
    register uint64_t x0 __asm__("x0") = guard;
    register uint64_t x1 __asm__("x1") = fd;
    register uint64_t x2 __asm__("x2") = buf;
    register uint64_t x3 __asm__("x3") = nbyte;
    register uint64_t x16 __asm__("x16") = 0x169;

    __asm__ volatile(
        "svc #0x80\n"
        "mov x1, xzr\n"
        "b.lo 1f\n"
        "mov x1, x0\n"
        "mov x0, #-1\n"
        "1:\n"
        : "+r"(x0), "+r"(x1)
        : "r"(x2), "r"(x3), "r"(x16)
        : "memory", "cc"
    );
    return (int64_t)x0;
}

/* ── 0x6038: Mach trap -24 — mach_reply_port ─────────────────────── */
mach_port_t e2_trap_mach_reply_port(void)
{
    register uint64_t x16 __asm__("x16") = (uint64_t)(int64_t)(-24);
    register uint64_t x0 __asm__("x0");

    __asm__ volatile("svc #0x80" : "=r"(x0) : "r"(x16) : "memory");
    return (mach_port_t)x0;
}

/* ── 0x6044: Mach trap -26 — thread_self_trap ────────────────────── */
mach_port_t e2_trap_thread_self(void)
{
    register uint64_t x16 __asm__("x16") = (uint64_t)(int64_t)(-26);
    register uint64_t x0 __asm__("x0");

    __asm__ volatile("svc #0x80" : "=r"(x0) : "r"(x16) : "memory");
    return (mach_port_t)x0;
}

/* ── 0x6050: Mach trap -27 — task_self_trap ──────────────────────── */
mach_port_t e2_trap_task_self(void)
{
    register uint64_t x16 __asm__("x16") = (uint64_t)(int64_t)(-27);
    register uint64_t x0 __asm__("x0");

    __asm__ volatile("svc #0x80" : "=r"(x0) : "r"(x16) : "memory");
    return (mach_port_t)x0;
}

/* ── 0x605c: Mach trap -28 — host_self_trap ──────────────────────── */
mach_port_t e2_trap_host_self(void)
{
    register uint64_t x16 __asm__("x16") = (uint64_t)(int64_t)(-28);
    register uint64_t x0 __asm__("x0");

    __asm__ volatile("svc #0x80" : "=r"(x0) : "r"(x16) : "memory");
    return (mach_port_t)x0;
}

/* ── 0x6068: Mach trap -18 — _kernelrpc_mach_port_deallocate_trap ── */
kern_return_t e2_trap_port_dealloc(mach_port_t task, mach_port_t port)
{
    register uint64_t x0 __asm__("x0") = task;
    register uint64_t x1 __asm__("x1") = port;
    register uint64_t x16 __asm__("x16") = (uint64_t)(int64_t)(-18);

    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x16) : "memory");
    return (kern_return_t)x0;
}

/* ── 0x6074: Mach trap -31 — mach_msg_trap ───────────────────────── */
kern_return_t e2_trap_mach_msg(void *msg, uint32_t option, uint32_t send_size,
                               uint32_t rcv_size, mach_port_t rcv_name,
                               uint32_t timeout, mach_port_t notify)
{
    register uint64_t x0 __asm__("x0") = (uint64_t)msg;
    register uint64_t x1 __asm__("x1") = option;
    register uint64_t x2 __asm__("x2") = send_size;
    register uint64_t x3 __asm__("x3") = rcv_size;
    register uint64_t x4 __asm__("x4") = rcv_name;
    register uint64_t x5 __asm__("x5") = timeout;
    register uint64_t x6 __asm__("x6") = notify;
    register uint64_t x16 __asm__("x16") = (uint64_t)(int64_t)(-31);

    __asm__ volatile("svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x16)
        : "memory");
    return (kern_return_t)x0;
}

/* ── 0x6080: Mach trap -47 — pid_for_task ────────────────────────── */
int e2_trap_pid_for_task(mach_port_t task)
{
    register uint64_t x0 __asm__("x0") = task;
    register uint64_t x16 __asm__("x16") = (uint64_t)(int64_t)(-47);

    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory");
    return (int)x0;
}

/* ── 0x608c: Mach trap -12 — _kernelrpc_mach_vm_deallocate_trap ──── */
kern_return_t e2_trap_vm_dealloc(mach_port_t task, uint64_t addr, uint64_t size)
{
    register uint64_t x0 __asm__("x0") = task;
    register uint64_t x1 __asm__("x1") = addr;
    register uint64_t x2 __asm__("x2") = size;
    register uint64_t x16 __asm__("x16") = (uint64_t)(int64_t)(-12);

    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "memory");
    return (kern_return_t)x0;
}

/* ── 0x6098: Mach trap -19 — _kernelrpc_mach_port_mod_refs_trap ──── */
kern_return_t e2_trap_port_mod_refs(mach_port_t task, mach_port_t port,
                                     uint32_t right, int32_t delta)
{
    register uint64_t x0 __asm__("x0") = task;
    register uint64_t x1 __asm__("x1") = port;
    register uint64_t x2 __asm__("x2") = right;
    register uint64_t x3 __asm__("x3") = (uint64_t)(int64_t)delta;
    register uint64_t x16 __asm__("x16") = (uint64_t)(int64_t)(-19);

    __asm__ volatile("svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x16)
        : "memory");
    return (kern_return_t)x0;
}
