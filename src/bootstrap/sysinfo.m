/*
 * sysinfo.m - System information gathering and device checks
 *
 * Decompiled from bootstrap.dylib offsets 0x7090-0x7b9c
 */

#import "bootstrap.h"
#import <string.h>
#import <stdlib.h>
#import <unistd.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <CoreFoundation/CoreFoundation.h>

extern int sandbox_check(pid_t pid, const char *operation, int type, ...);
extern int SANDBOX_CHECK_NO_REPORT;
extern int sysctlbyname(const char *, void *, size_t *, void *, size_t);

extern kern_return_t host_kernel_version(mach_port_t, char *);

/* ── get_cpufamily ─────────────────────────────────────────────── */
/* Replacement for broken _get_cpu_capabilities commpage access.
 * The original binary read CPUFAMILY from commpage offset +0x80
 * via the GOT layout — that layout doesn't exist in our recompile.
 * Use the stable sysctl interface instead.
 */

static uint32_t get_cpufamily(void)
{
    uint32_t cpufamily = 0;
    size_t size = sizeof(cpufamily);
    if (sysctlbyname("hw.cpufamily", &cpufamily, &size, NULL, 0) != 0) {
        print_log("[bootstrap] get_cpufamily: sysctl FAIL");
        return 0;
    }
    return cpufamily;
}

/* ── read_plist (0x7a98) ────────────────────────────────────────── */

void *read_plist(const char *path)
{
    print_log("[bootstrap] read_plist: %s", path);

    CFErrorRef error = NULL;
    CFAllocatorRef alloc = kCFAllocatorDefault;

    size_t len = strlen(path);
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(alloc, (const UInt8 *)path, len, false);
    if (!url)
        return NULL;

    CFReadStreamRef stream = CFReadStreamCreateWithFile(alloc, url);
    if (!stream) {
        CFRelease(url);
        return NULL;
    }

    if (!CFReadStreamOpen(stream)) {
        CFRelease(url);
        CFRelease(stream);
        return NULL;
    }

    CFPropertyListRef plist = CFPropertyListCreateWithStream(
        alloc, stream, 0, kCFPropertyListImmutable, NULL, &error);

    if (!plist && error)
        CFRelease(error);

    CFReadStreamClose(stream);
    CFRelease(url);
    CFRelease(stream);
    return (void *)plist;
}

/* ── get_os_version (0x7090) ────────────────────────────────────── */

int get_os_version(uint32_t *out)
{
    int patch = 0;

    CFDictionaryRef plist = (CFDictionaryRef)read_plist(
        "/System/Cryptexes/OS/System/Library/CoreServices/SystemVersion.plist");
    if (!plist) {
        plist = (CFDictionaryRef)read_plist(
            "/System/Library/CoreServices/SystemVersion.plist");
        if (!plist) {
            print_log("[bootstrap] get_os_version: FAIL no SystemVersion.plist");
            return -1;
        }
    }

    CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault,
                                                 "ProductVersion", kCFStringEncodingUTF8);
    if (!key) {
        CFRelease(plist);
        return -1;
    }

    CFTypeRef value = CFDictionaryGetValue(plist, key);
    if (!value) {
        CFRelease(key);
        CFRelease(plist);
        return -1;
    }

    if (CFGetTypeID(value) != CFStringGetTypeID()) {
        CFRelease(key);
        CFRelease(plist);
        return -1;
    }

    char buf[0x20];
    Boolean ok = CFStringGetCString((CFStringRef)value, buf, 0x20, CFStringGetSystemEncoding());
    CFRelease(key);
    CFRelease(plist);

    if (!ok)
        return -1;

    int major = 0, minor = 0;
    if (sscanf(buf, "%d.%d.%d", &major, &minor, &patch) < 2)
        return -2;

    *out = (uint32_t)((major << 16) | (minor << 8) | patch);
    print_log("[bootstrap] get_os_version: %s -> 0x%x (major=%d minor=%d patch=%d)", buf, *out, major, minor, patch);
    return 0;
}

/* ── check_virtual_env (0x71fc) ─────────────────────────────────── */

uint32_t check_virtual_env(uint8_t *result)
{
    if (!result)
        return -1;

    print_log("[bootstrap] check_virtual_env: start");

    struct stat st;
    memset(&st, 0, sizeof(st));

    if (stat("/usr/libexec/corelliumd", &st) == 0) {
        print_log("[bootstrap] check_virtual_env: Corellium daemon found");
        *result = 0;
        return 0;
    }

    if (sandbox_check(getpid(), "iokit-get-properties",
                      SANDBOX_CHECK_NO_REPORT,
                      "IOPlatformSerialNumber") > 0)
        goto cpu_check;

    {
        void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit", 1);
        if (!iokit)
            goto cpu_check;

        void *sym_master = dlsym(iokit, "kIOMasterPortDefault");
        uint64_t master_ptr = strip_pac((uint64_t)sym_master);

        void *sym_entry = dlsym(iokit, "IORegistryEntryFromPath");
        uint64_t entry_fn = strip_pac((uint64_t)sym_entry);

        void *sym_prop = dlsym(iokit, "IORegistryEntryCreateCFProperty");
        uint64_t prop_fn = strip_pac((uint64_t)sym_prop);

        void *sym_release = dlsym(iokit, "IOObjectRelease");
        uint64_t release_fn = strip_pac((uint64_t)sym_release);

        if (!entry_fn || !prop_fn || !release_fn || !master_ptr) {
            dlclose(iokit);
            goto cpu_check;
        }

        typedef uint32_t (*io_entry_fn_t)(uint32_t, const char *);
        uint32_t master = *(uint32_t *)master_ptr;
        uint32_t entry = ((io_entry_fn_t)entry_fn)(master, "IODeviceTree:/");
        if (!entry) {
            dlclose(iokit);
            goto cpu_check;
        }

        CFStringRef serial_key = CFStringCreateWithCString(
            kCFAllocatorDefault, "IOPlatformSerialNumber", kCFStringEncodingUTF8);

        int serial_ok = -1;
        char serial_buf[0x40];
        memset(serial_buf, 0, sizeof(serial_buf));

        if (!serial_key) {
            serial_ok = -1;
        } else {
            typedef CFTypeRef (*io_prop_fn_t)(uint32_t, CFStringRef, CFAllocatorRef, uint32_t);
            CFTypeRef prop = ((io_prop_fn_t)prop_fn)(entry, serial_key, kCFAllocatorDefault, 0);

            if (!prop || CFStringGetTypeID() != CFGetTypeID(prop)) {
                serial_ok = -1;
            } else {
                Boolean got = CFStringGetCString((CFStringRef)prop, serial_buf, 0x40, kCFStringEncodingUTF8);
                serial_ok = got ? 0 : -1;
                CFRelease(prop);
            }

            CFRelease(serial_key);
        }

        typedef void (*io_release_fn_t)(uint32_t);
        ((io_release_fn_t)release_fn)(entry);
        dlclose(iokit);

        if (serial_ok == 0) {
            print_log("[bootstrap] check_virtual_env: serial=%s", serial_buf);
            uint64_t first8 = *(uint64_t *)serial_buf;
            uint64_t corelliu = 0x49554C4C45524F43ULL;
            uint8_t ninth = serial_buf[8];
            memset(serial_buf, 0, sizeof(serial_buf));

            if ((first8 ^ corelliu) == 0 && (ninth ^ 0x4D) == 0) {
                print_log("[bootstrap] check_virtual_env: CORELLIUM serial detected");
                *result = 0;
                return 0;
            }
        }
    }

cpu_check:
    /* Original binary read from commpage via _get_cpu_capabilities GOT
     * offset chain. That layout doesn't exist in our recompile.
     * Use hw.cpufamily sysctl instead for SoC identification.
     * The VM-specific bit checks (commpage +0x10 bit 26, +0x26 == 0x80)
     * cannot be replicated via sysctl — Corellium detection above
     * already covers the main virtual environment case.
     */
    {
        uint32_t soc = get_cpufamily();
        print_log("[bootstrap] check_virtual_env: cpufamily=0x%x", soc);

        if (soc == 0) {
            /* Can't determine CPU family */
            *result = 0;
            return -1;
        }

        /* Real hardware detected — Corellium checks above didn't trigger */
        *result = 1;
        print_log("[bootstrap] check_virtual_env: result=%d", *result);
        return 0;
    }
}

/* ── check_device_a (0x7524) ────────────────────────────────────── */

int check_device_a(uint8_t *out)
{
    if (!out)
        return -1;

    *out = 0;
    uint32_t soc = get_cpufamily();
    if (!soc)
        return -2;

    uint8_t device = 0;

    if (soc <= (int32_t)SOC_TYPE_C) {
        if (soc == SOC_TYPE_A || soc == SOC_TYPE_B) {
            if (check_virtual_env(&device) != 0)
                return -3;
        }
    } else {
        if (soc == SOC_TYPE_D || soc == SOC_TYPE_E || soc == SOC_TYPE_F) {
            if (check_virtual_env(&device) != 0)
                return -3;
        }
    }

    *out = device;
    print_log("[bootstrap] check_device_a: cpufamily=0x%x device=%d", soc, device);
    return 0;
}

/* ── check_device_b (0x7638) ────────────────────────────────────── */

int check_device_b(uint8_t *out)
{
    if (!out)
        return -1;

    uint32_t soc = get_cpufamily();
    if (!soc)
        return -2;

    if (soc == SOC_DEVICE_B_A || soc == SOC_DEVICE_B_B) {
        uint8_t device = 1;
        if (check_virtual_env(&device) != 0)
            return -3;
        *out = device;
    } else {
        *out = 0;
    }
    print_log("[bootstrap] check_device_b: cpufamily=0x%x out=%d", soc, *out);
    return 0;
}

/* ── init_system_info (0x7720) ──────────────────────────────────── */

uint32_t init_system_info(bootstrap_ctx_t *ctx)
{
    print_log("[bootstrap] init_system_info: start");

    mach_msg_type_number_t count = 5;
    struct {
        uint64_t all_images_addr;
        uint64_t all_images_size;
    } dyld_info;
    memset(&dyld_info, 0, sizeof(dyld_info));

    kern_return_t kr = task_info(mach_task_self(), 17,
                                 (task_info_t)&dyld_info, &count);

    uint64_t all_images = dyld_info.all_images_addr;
    if (kr != 0 || !all_images) {
        print_log("[bootstrap] init_system_info: task_info FAIL kr=%d", kr);
        return -1;
    }

    uint64_t info_array = *(uint64_t *)((uint8_t *)all_images + 0x20);
    if (!info_array)
        return -1;

    uint32_t soc_ver = *(uint32_t *)((uint8_t *)info_array + 0x4);
    uint32_t soc_sub = *(uint32_t *)((uint8_t *)info_array + 0x8) & 0xFFFFFF;
    ctx->soc_version = soc_ver;
    ctx->soc_subversion = soc_sub;
    print_log("[bootstrap] init_system_info: soc_ver=0x%x soc_sub=0x%x", soc_ver, soc_sub);

    uint32_t n_images = *(uint32_t *)((uint8_t *)all_images + 0x4);
    if (!n_images)
        return -1;

    uint8_t *image_list = *(uint8_t **)((uint8_t *)all_images + 0x8);
    if (!image_list)
        return -1;

    char *path0 = *(char **)(image_list + 0x8);
    uint8_t is_wc = 0;
    if (strstr(path0, "WebContent")) {
        is_wc = 1;
    } else {
        uint8_t *last = image_list + (uint64_t)(n_images - 1) * 0x18;
        char *path_last = *(char **)(last + 0x8);
        is_wc = strstr(path_last, "WebContent") ? 1 : 0;
    }
    ctx->is_webcontent = is_wc;
    print_log("[bootstrap] init_system_info: is_webcontent=%d", is_wc);

    /* Use sysctl for CPU identification instead of commpage reads */
    uint32_t cpufamily = get_cpufamily();
    if (!cpufamily) {
        print_log("[bootstrap] init_system_info: get_cpufamily FAIL");
        return -1;
    }
    ctx->cpu_type = cpufamily;

    /* cpu_features: not used by bootstrap itself, set to 0.
     * Original binary read from commpage offset +0x38 which is
     * no longer accessible via our recompiled GOT layout. */
    ctx->cpu_features = 0;
    print_log("[bootstrap] init_system_info: cpu_type=0x%x (cpufamily)", ctx->cpu_type);

    uint32_t os_ver;
    int ret = get_os_version(&os_ver);
    if (ret != 0) {
        print_log("[bootstrap] init_system_info: get_os_version FAIL ret=%d", ret);
        return ret;
    }

    ctx->os_version = os_ver;

    char kern_str_[0x200] = {0};
    char *kern_str = kern_str_;

    if ((os_ver & 0xFE0000) > 0xD0000) {
        uint32_t name[2] = { CTL_KERN, KERN_VERSION };
        size_t len = 0x200;
        if (sysctl((int *)name, 2, kern_str, &len, NULL, 0) != 0) {
            print_log("[bootstrap] init_system_info: sysctl kern FAIL");
            return -2;
        }
    } else {
        if (host_kernel_version(mach_host_self(), kern_str) != 0)
            return -2;
    }

    print_log("[bootstrap] init_system_info: kernel=%s", kern_str);

    if (!strstr(kern_str, "RELEASE")) {
        print_log("[bootstrap] init_system_info: kernel is not RELEASE");
        return -3;
    }

    if (!(kern_str = strstr(kern_str, "xnu-"))) {
        print_log("[bootstrap] init_system_info: kernel does not contain xnu-");
        return -4;
    }

    uint32_t xnu_maj = 0, xnu_min = 0, xnu_rev = 0, xnu_bld = 0, xnu_sub = 0;
    if (sscanf(kern_str, "xnu-%d.%d.%d.%d.%d%*s",
               &xnu_maj, &xnu_min, &xnu_rev, &xnu_bld, &xnu_sub) <= 2) {
        print_log("[bootstrap] init_system_info: kernel version parsing failed");
        //return -5;
    }

    ctx->kernel_version = (xnu_maj << 18) | (xnu_min << 9) | xnu_rev;

    uint64_t xv = ((uint64_t)(xnu_maj & 0x7FFF) << 20) |
                   ((uint64_t)xnu_min << 10) |
                   (uint64_t)(xnu_rev & 0x3FF);
    xv = (xv << 20) | ((uint64_t)(xnu_bld << 10) & 0xFFC00) |
         (uint64_t)(xnu_sub & 0x3FF);
    ctx->xnu_version = xv;

    uint8_t dev_type;
    if (check_device_b(&dev_type) != 0) {
        print_log("[bootstrap] init_system_info: check_device_b FAIL");
        return ret;
    }
    ctx->flag_is_release = dev_type;

    uint8_t dev_a;
    if (check_device_a(&dev_a) != 0) {
        print_log("[bootstrap] init_system_info: check_device_a FAIL");
        return ret;
    }

    ctx->flag_device_type = dev_a;

    uint8_t new_ios = 0;
    if (soc_ver == 0x01000C && soc_sub >= 2) {
        uint8_t major = (os_ver >> 16) & 0xFF;
        if (major > 12) {
            new_ios = 1;
        } else if (major == 12) {
            new_ios = ((os_ver & 0xFF00) != 0) ? 1 : 0;
        }
    }
    ctx->flag_new_ios = new_ios;

    uint8_t a15_feat = 0;
    if (dev_a) {
        uint32_t ver = ctx->os_version;
        if ((ver >> 10) >= 0x3C1) {
            uint32_t cpu = ctx->cpu_type;
            if (cpu == SOC_TYPE_A || cpu == SOC_TYPE_B || cpu == SOC_TYPE_F) {
                a15_feat = 1;
            }
        }
    }
    ctx->flag_a15_features = a15_feat;

    print_log("[bootstrap] init_system_info: OK os=0x%x new_ios=%d dev_a=%d a15=%d", os_ver, new_ios, dev_a, a15_feat);
    return 0;
}
