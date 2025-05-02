#include <stdint.h>

typedef int cpu_type_t;
typedef int cpu_subtype_t;

#define MH_MAGIC        0xfeedface
#define MH_CIGAM        0xcefaedfe

#define MH_MAGIC_64     0xfeedfacf
#define MH_CIGAM_64     0xcffaedfe

struct mach_header_64 {
    uint32_t        magic;
    cpu_type_t      cputype;
    cpu_subtype_t   cpusubtype;
    uint32_t        filetype;
    uint32_t        ncmds;
    uint32_t        sizeofcmds;
    uint32_t        flags;
    uint32_t        reserved;
};

#define CPU_ARCH_MASK           0xff000000
#define CPU_ARCH_ABI64          0x01000000

#define CPU_TYPE_ARM            ((cpu_type_t) 12)
#define CPU_TYPE_ARM64          (CPU_TYPE_ARM | CPU_ARCH_ABI64)

#define CPU_SUBTYPE_MASK        0xff000000
#define CPU_SUBTYPE_LIB64       0x80000000
#define CPU_SUBTYPE_ARM64_ALL   ((cpu_subtype_t) 0)
#define CPU_SUBTYPE_ARM64E      ((cpu_subtype_t) 2)

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct build_version_command {
    uint32_t        cmd;
    uint32_t        cmdsize;
    uint32_t        platform;
    uint32_t        minos;
    uint32_t        sdk;
    uint32_t        ntools;
};

#define LC_BUILD_VERSION        0x32

#define PLATFORM_MACOS          1
#define PLATFORM_IOS            2
#define PLATFORM_TVOS           3
#define PLATFORM_WATCHOS        4
#define PLATFORM_BRIDGEOS       5
#define PLATFORM_MACCATALYST    6
#define PLATFORM_IOSSIMULATOR   7
#define PLATFORM_TVOSSIMULATOR  8
#define PLATFORM_WATCHOSSIMULATOR 9

#define FAT_MAGIC       0xcafebabe
#define FAT_CIGAM       0xbebafeca

struct fat_header {
    uint32_t        magic;
    uint32_t        nfat_arch;
};

struct fat_arch {
    cpu_type_t      cputype;
    cpu_subtype_t   cpusubtype;
    uint32_t        offset;
    uint32_t        size;
    uint32_t        align;
};
