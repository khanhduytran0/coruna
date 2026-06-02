@import Darwin;
#include "ida_types.h"

 enum CPUFamily : uint32_t
 {
     CPUFamily_A8  = 0x2C91A47E,
     CPUFamily_A9  = 0x92FB37C8,
     CPUFamily_A10 = 0x67CEEE93,
     CPUFamily_A11 = 0xE81E7EF6,
     CPUFamily_A12 = 0x7D34B9F,
     CPUFamily_A13 = 0x462504D2,
     CPUFamily_A14 = 0x1B588BB3,
     CPUFamily_A15 = 0xDA33D83D,
     CPUFamily_A16 = 0x8765EDEA,
     CPUFamily_A17 = 0x2876F5B5,
 };

 typedef struct struct_krwCtx // sizeof=0x1D50
 {
     _DWORD flags;
     _BYTE gap4[168];
     uint32_t threadForKernelRead;
     _BYTE gap42[144];
     int xnuMajorVersion;
     _BYTE gap144[20];
     _QWORD someLargeNumber;
     _BYTE gap160[8];
     int stride168;
     int gap16C[7];
     _QWORD pageMask;
     _BYTE gap190[200];
     int isRW;
     struct mach_timebase_info timebase;
     mach_port_t semaphore;
     pthread_mutex_t someMutex;
     uint32_t someInt1;
     uint32_t someInt2;
     uint64_t gap191[851];
     _QWORD IOKitConnInfo;
 } struct_krwCtx;

 typedef struct __attribute__((packed)) __attribute__((aligned(4))) struct_IOKitConnInfo // sizeof=0x74
 {
     _BYTE gap0[80];
     _QWORD qword50;
     _QWORD qword58;
     _QWORD qword60;
     _QWORD qword68;
     _DWORD dword70;
 } struct_IOKitConnInfo;

 typedef struct __attribute__((packed)) __attribute__((aligned(8))) struct_xnuMajorVersion // sizeof=0x28
 {                                       // XREF: driver_init2_1/r
     _OWORD majorVersion;
     _OWORD oword10;                     // XREF: driver_init2_1+48/w
                                         // driver_init2_1+10C/r ...
     _QWORD qword20;                     // XREF: driver_init2_1+40/w
                                         // driver_init2_1+114/r ...
 } struct_xnuMajorVersion;

 typedef struct __attribute__((packed)) __attribute__((aligned(2))) struct_v83 // sizeof=0x102
 {
     _BYTE gap0[48];
     _DWORD dword30;
     _BYTE gap34[4];
     _DWORD dword38;
     _BYTE gap3C[52];
     _OWORD xnuMajorVersion;
     _OWORD oword80;
     _QWORD qword90;
     _DWORD dword98;
     _BYTE gap9C[12];
     _QWORD qwordA8;
     _BYTE gapB0[81];
     _BYTE byte101;
 } struct_v83;

 typedef struct __attribute__((packed)) __attribute__((aligned(8))) struct_a1 // sizeof=0x128
 {
     _OWORD oword0;
     _OWORD oword10;
     _OWORD oword20;
     _OWORD oword30;
     _OWORD oword40;
     _OWORD oword50;
     _OWORD oword60;
     _OWORD xnuMajorVersion;
     _OWORD oword80;
     _OWORD oword90;
     _OWORD owordA0;
     _OWORD owordB0;
     _OWORD owordC0;
     _OWORD owordD0;
     _OWORD owordE0;
     _OWORD owordF0;
     _OWORD oword100;
     _OWORD oword110;
     _QWORD qword120;
 } struct_a1;
