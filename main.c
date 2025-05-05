//
//  main.c
//  machoe
//
//  Created by Ethan Arbuckle on 5/1/25.
//

#include <libgen.h>
#include <dirent.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#define _FILE_OFFSET_BITS 64

#if !defined(__APPLE__)
#include <byteswap.h>
#include <stddef.h>
#include "darwin_defines.h"
#define OSSwapInt32(x) bswap_32(x)

#else

#include <libkern/OSByteOrder.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#endif

typedef struct {
    const char *input_path;
    const char *output_path;
    bool recursive;
    bool modify_cpu;
    cpu_subtype_t target_subtype;
    bool modify_platform;
    uint32_t target_platform;
    uint32_t target_minos;
    uint32_t target_sdk;
    bool verbose;
    bool convert_to_dylib;
} tool_config_t;


static bool remove_lc_main(uint8_t *commands, uint32_t ncmds, uint32_t *sizeofcmds) {
    uint8_t *p = commands;
    for (uint32_t i = 0; i < ncmds; i++) {
        struct load_command *lc = (struct load_command *)p;
        if (lc->cmd == LC_MAIN) {
            uint32_t size = lc->cmdsize;
            memmove(p, p + size, *sizeofcmds - (p - commands) - size);
            *sizeofcmds -= size;
            return true;
        }

        p += lc->cmdsize;
    }

    return false;
}

static void patch_pagezero(uint8_t *commands, uint32_t ncmds) {
    uint8_t *p = commands;
    for (uint32_t i = 0; i < ncmds; i++) {
        struct load_command *lc = (struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)p;
            if (strcmp(seg->segname, "__PAGEZERO") == 0) {
                strncpy(seg->segname, "__dylibolical", sizeof(seg->segname));
                seg->vmsize = 0x4000;
                seg->vmaddr -= 0x4000;
            }
        }

        p += lc->cmdsize;
    }
}

static bool add_lc_id_dylib(uint8_t *commands, uint32_t *ncmds, uint32_t *sizeofcmds, size_t maxcmdsize, const char *dylib_path) {
    size_t name_len = strlen(dylib_path) + 1;
    uint32_t padded_size = (sizeof(struct dylib_command) + name_len + 7) & ~7;

    if (*sizeofcmds + padded_size > maxcmdsize) {
        return false;
    }

    struct dylib_command *idcmd = (struct dylib_command *)(commands + *sizeofcmds);
    memset(idcmd, 0, padded_size);
    idcmd->cmd = LC_ID_DYLIB;
    idcmd->cmdsize = padded_size;
    idcmd->dylib.name.offset = sizeof(struct dylib_command);
    idcmd->dylib.timestamp = 1;
    idcmd->dylib.current_version = 0x10000;
    idcmd->dylib.compatibility_version = 0x10000;
    memcpy((uint8_t *)idcmd + sizeof(struct dylib_command), dylib_path, name_len);

    *ncmds += 1;
    *sizeofcmds += padded_size;
    return true;
}

static void transform_executable_to_dylib(void *mapped, size_t filesize, const char *basename) {
    struct mach_header_64 *header = (struct mach_header_64 *)mapped;
    uint8_t *commands = (uint8_t *)(header + 1);
    size_t maxcmdsize = filesize - sizeof(*header);

    header->filetype = MH_DYLIB;
    header->flags &= ~MH_PIE;

    if (remove_lc_main(commands, header->ncmds, &header->sizeofcmds)) {
        header->ncmds--;
    }

    patch_pagezero(commands, header->ncmds);

    char dylib_name[256];
    if (strstr(basename, ".dylib") == NULL) {
        snprintf(dylib_name, sizeof(dylib_name), "@rpath/%s.dylib", basename);
    }
    else {
        snprintf(dylib_name, sizeof(dylib_name), "@rpath/%s", basename);
    }

    if (!add_lc_id_dylib(commands, &header->ncmds, &header->sizeofcmds, maxcmdsize, dylib_name)) {
        printf("Not enough room to add LC_ID_DYLIB\n");
    }
}

bool parse_version(const char *version_str, uint32_t *version_out) {
    uint32_t major = 0;
    uint32_t minor = 0;
    uint32_t patch = 0;
    int fields = sscanf(version_str, "%u.%u.%u", &major, &minor, &patch);
    if (fields < 2 || major > 0xFFFF || minor > 0xFF || patch > 0xFF) {
        return false;
    }

    *version_out = (major << 16) | (minor << 8) | patch;
    return true;
}

bool platform_name_to_id(const char *name, uint32_t *id_out) {
    if (name == NULL || id_out == NULL) {
        return false;
    }

    if (strcasecmp(name, "macos") == 0) {
        *id_out = PLATFORM_MACOS;
    }
    else if (strcasecmp(name, "ios") == 0) {
        *id_out = PLATFORM_IOS;
    }
    else if (strcasecmp(name, "tvos") == 0) {
        *id_out = PLATFORM_TVOS;
    }
    else if (strcasecmp(name, "watchos") == 0) {
        *id_out = PLATFORM_WATCHOS;
    }
    else if (strcasecmp(name, "bridgeos") == 0) {
        *id_out = PLATFORM_BRIDGEOS;
    }
    else if (strcasecmp(name, "mac-catalyst") == 0) {
        *id_out = PLATFORM_MACCATALYST;
    }
    else if (strcasecmp(name, "ios-simulator") == 0) {
        *id_out = PLATFORM_IOSSIMULATOR;
    }
    else if (strcasecmp(name, "tvos-simulator") == 0) {
        *id_out = PLATFORM_TVOSSIMULATOR;
    }
    else if (strcasecmp(name, "watchos-simulator") == 0) {
        *id_out = PLATFORM_WATCHOSSIMULATOR;
    }
    else {
        return false;
    }
    
    return true;
}

const char *platform_id_to_name(uint32_t id) {
    switch (id) {
        case PLATFORM_MACOS: {
            return "macOS";
        }
        case PLATFORM_IOS: {
            return "iOS";
        }
        case PLATFORM_TVOS: {
            return "tvOS";
        }
        case PLATFORM_WATCHOS: {
            return "watchOS";
        }
        case PLATFORM_BRIDGEOS: {
            return "bridgeOS";
        }
        case PLATFORM_MACCATALYST: {
            return "Mac Catalyst";
        }
        case PLATFORM_IOSSIMULATOR: {
            return "iOS Simulator";
        }
        case PLATFORM_TVOSSIMULATOR: {
            return "tvOS Simulator";
        }
        case PLATFORM_WATCHOSSIMULATOR: {
            return "watchOS Simulator";
        }
        default: {
            return "Unknown";
        }
    }
}

bool subtype_name_to_id(const char *name, cpu_subtype_t *id_out) {
    if (name == NULL || id_out == NULL) {
        return false;
    }

    if (strcasecmp(name, "arm64") == 0) {
        *id_out = CPU_SUBTYPE_ARM64_ALL;
        return true;
    }
    else if (strcasecmp(name, "arm64e") == 0) {
        *id_out = CPU_SUBTYPE_ARM64E;
        return true;
    }

    return false;
}

const char *subtype_id_to_name(cpu_subtype_t id) {
    cpu_subtype_t base_id = id & ~CPU_SUBTYPE_MASK;
    if (base_id == CPU_SUBTYPE_ARM64E) {
        return "arm64e";
    }
    else if (base_id == CPU_SUBTYPE_ARM64_ALL) {
        return "arm64";
    }

    return "Unknown Subtype";
}

bool process_macho_slice(FILE *file, off_t slice_offset, size_t slice_size, const tool_config_t *config) {
    if (fseeko(file, slice_offset, SEEK_SET) != 0) {
        printf("Failed to seek to slice offset %lld: %s\n", slice_offset, strerror(errno));
        return false;
    }

    struct mach_header_64 header;
    if (fread(&header, sizeof(header), 1, file) != 1) {
        printf("Failed to read mach_header_64 at offset %lld\n", slice_offset);
        return false;
    }

    if (header.magic != MH_MAGIC_64) {
        if (config->verbose) {
            printf("Skipping non-MH_MAGIC_64 slice at offset %lld (magic: 0x%x)\n", slice_offset, header.magic);
        }
        return false;
    }

    if (header.cputype != CPU_TYPE_ARM64) {
        if (config->verbose) {
            printf("Skipping non-ARM64 slice at offset %lld (cputype: %d)\n", slice_offset, header.cputype);
        }
        return false;
    }

    if (header.sizeofcmds > slice_size - sizeof(struct mach_header_64)) {
        printf("Invalid sizeofcmds in header at offset %lld (sizeofcmds: %u, slice size: %zu)\n", slice_offset, header.sizeofcmds, slice_size);
        return false;
    }

    bool modified = false;

    if (config->convert_to_dylib && header.filetype == MH_EXECUTE) {
        int fd = fileno(file);
        void *mapped = mmap(NULL, slice_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, slice_offset);
        if (mapped == MAP_FAILED) {
            printf("Failed to mmap slice at offset %lld\n", slice_offset);
            return false;
        }

        const char *base = basename((char *)config->input_path);
        transform_executable_to_dylib(mapped, slice_size, base);
        msync(mapped, slice_size, MS_SYNC);

        munmap(mapped, slice_size);
        modified = true;

        if (config->verbose) {
            printf("Converted slice at offset %lld to MH_DYLIB\n", slice_offset);
        }

        if (fseeko(file, slice_offset, SEEK_SET) != 0 || fread(&header, sizeof(header), 1, file) != 1) {
            printf("Failed to reread header after dylib transform\n");
            return false;
        }
    }

    if (config->modify_cpu) {
        cpu_subtype_t current_subtype = header.cpusubtype;
        cpu_subtype_t current_base_subtype = current_subtype & ~CPU_SUBTYPE_LIB64;
        cpu_subtype_t target_base_subtype = config->target_subtype & ~CPU_SUBTYPE_LIB64;

        if (current_base_subtype != target_base_subtype) {
            if (config->verbose) {
                printf("Slice at offset %lld: Changing CPU subtype from %s (0x%x) to %s (0x%x)\n", slice_offset, subtype_id_to_name(current_subtype), current_subtype, subtype_id_to_name(config->target_subtype), config->target_subtype);
            }

            header.cpusubtype = config->target_subtype | (current_subtype & CPU_SUBTYPE_LIB64);
            modified = true;
        }
    }

    if (config->modify_platform) {
        uint32_t original_sizeofcmds = header.sizeofcmds;
        bool build_version_found = false;

        uint32_t cmd_offset = (uint32_t)slice_offset + sizeof(struct mach_header_64);
        for (uint32_t i = 0; i < header.ncmds; i++) {
            struct load_command lc;
            if (fseeko(file, cmd_offset, SEEK_SET) != 0) {
                printf("Failed to seek to load command %u at offset %u: %s\n", i, cmd_offset, strerror(errno));
                return false;
            }

            if (fread(&lc, sizeof(struct load_command), 1, file) != 1) {
                printf("Failed to read load command %u at offset %u\n", i, cmd_offset);
                return false;
            }

            if (lc.cmdsize < sizeof(struct load_command) || lc.cmdsize == 0 || cmd_offset + lc.cmdsize > slice_offset + slice_size) {
                printf("Invalid cmdsize %u for command %u (cmd 0x%x) at offset %u\n", lc.cmdsize, i, lc.cmd, cmd_offset);
                return false;
            }

            if (lc.cmd == LC_BUILD_VERSION) {
                if (lc.cmdsize < sizeof(struct build_version_command)) {
                    printf("LC_BUILD_VERSION command too small at offset %u (size: %u, expected: %zu)\n",
                           cmd_offset, lc.cmdsize, sizeof(struct build_version_command));
                    return false;
                }
                
                if (fseeko(file, cmd_offset, SEEK_SET) != 0) {
                    printf("Failed to re-seek to LC_BUILD_VERSION at %u: %s\n", cmd_offset, strerror(errno));
                    return false;
                }

                struct build_version_command bvc;
                if (fread(&bvc, sizeof(struct build_version_command), 1, file) != 1) {
                    printf("Failed to read LC_BUILD_VERSION command at offset %u\n", cmd_offset);
                    return false;
                }

                if (bvc.platform != config->target_platform || bvc.minos != config->target_minos || bvc.sdk != config->target_sdk) {
                    if (config->verbose) {
                        printf("Slice at offset %lld: Modifying LC_BUILD_VERSION: platform %s (0x%x) -> %s (0x%x), minos 0x%x -> 0x%x, sdk 0x%x -> 0x%x\n", slice_offset, platform_id_to_name(bvc.platform), bvc.platform, platform_id_to_name(config->target_platform), config->target_platform, bvc.minos, config->target_minos, bvc.sdk, config->target_sdk);
                    }

                    bvc.platform = config->target_platform;
                    bvc.minos = config->target_minos;
                    bvc.sdk = config->target_sdk;

                    if (fseeko(file, cmd_offset, SEEK_SET) != 0) {
                        printf("Failed to seek back to write LC_BUILD_VERSION at %u: %s\n", cmd_offset, strerror(errno));
                        return false;
                    }

                    if (fwrite(&bvc, sizeof(bvc), 1, file) != 1) {
                        printf("Failed to write modified LC_BUILD_VERSION at offset %u\n", cmd_offset);
                        return false;
                    }

                    modified = true;
                }

                build_version_found = true;
                break;
            }

            cmd_offset += lc.cmdsize;
        }

        if (!build_version_found) {
            uint32_t end_of_cmds_offset = (uint32_t)slice_offset + sizeof(struct mach_header_64) + original_sizeofcmds;
            if (end_of_cmds_offset + sizeof(struct build_version_command) > slice_offset + slice_size) {
                printf("Slice at offset %lld: Not enough space to add LC_BUILD_VERSION command\n", slice_offset);
                return false;
            }

            if (config->verbose) {
                printf("Slice at offset %lld: LC_BUILD_VERSION not found. Adding new command: platform %s (0x%x), minos 0x%x, sdk 0x%x\n", slice_offset, platform_id_to_name(config->target_platform), config->target_platform, config->target_minos, config->target_sdk);
            }

            struct build_version_command new_bvc = {
                .cmd = LC_BUILD_VERSION,
                .cmdsize = sizeof(struct build_version_command),
                .platform = config->target_platform,
                .minos = config->target_minos,
                .sdk = config->target_sdk,
                .ntools = 0};

            if (fseeko(file, end_of_cmds_offset, SEEK_SET) != 0) {
                printf("Failed to seek to end of load commands (%u) to add LC_BUILD_VERSION: %s\n", end_of_cmds_offset, strerror(errno));
                return false;
            }

            if (fwrite(&new_bvc, sizeof(new_bvc), 1, file) != 1) {
                printf("Failed to write new LC_BUILD_VERSION at offset %u\n", end_of_cmds_offset);
                return false;
            }

            header.ncmds++;
            header.sizeofcmds += sizeof(new_bvc);
            modified = true;
        }
    }

    if (modified) {
        if (fseeko(file, slice_offset, SEEK_SET) != 0) {
            printf("Failed to seek to slice start (%lld) to write updated header: %s\n", slice_offset, strerror(errno));
            return false;
        }
        
        if (fwrite(&header, sizeof(header), 1, file) != 1) {
            printf("Failed to write updated mach_header_64 at offset %lld\n", slice_offset);
            return false;
        }
        
        if (config->verbose) {
            printf("Slice at offset %lld: Header updated successfully\n", slice_offset);
        }
    }
    else {
        if (config->verbose) {
            printf("Slice at offset %lld: No changes made to header\n", slice_offset);
        }
    }
    return true;
}

bool process_single_macho(FILE *file, const char *filepath, uint32_t magic, struct stat *st, const tool_config_t *config) {
    if (magic == MH_CIGAM_64) {
        printf("Wrong endianness MH_CIGAM_64 in %s\n", filepath);
        return false;
    }
    else {
        return process_macho_slice(file, 0, st->st_size, config);
    }
}

bool process_arm64_slice(FILE *file, const char *filepath, struct fat_arch *arch, bool needs_swap, size_t file_size, const tool_config_t *config) {
    struct fat_arch arch_copy = *arch;
    if (needs_swap) {
        arch_copy.cputype = OSSwapInt32(arch_copy.cputype);
        arch_copy.cpusubtype = OSSwapInt32(arch_copy.cpusubtype);
        arch_copy.offset = OSSwapInt32(arch_copy.offset);
        arch_copy.size = OSSwapInt32(arch_copy.size);
    }

    if (config->verbose) {
        printf("ARM64 slice (subtype 0x%x) at offset %u, size %u\n", arch_copy.cpusubtype, arch_copy.offset, arch_copy.size);
    }

    if (arch_copy.offset == 0 || arch_copy.offset + arch_copy.size > file_size || arch_copy.size < sizeof(struct mach_header_64)) {
        printf("Invalid offset/size for fat arch %u in %s. Skipping slice\n", arch_copy.offset, filepath);
        return false;
    }

    return process_macho_slice(file, (off_t)arch_copy.offset, (size_t)arch_copy.size, config);
}

bool update_fat_arch_subtype(FILE *file, const char *filepath, uint32_t i, cpu_subtype_t current_subtype, cpu_subtype_t target_subtype, bool needs_swap, const tool_config_t *config) {
    cpu_subtype_t target_subtype_for_arch = target_subtype | (current_subtype & CPU_SUBTYPE_LIB64);
    if (current_subtype != target_subtype_for_arch) {
        if (config->verbose) {
            printf("Updating fat_arch entry %u cpusubtype to 0x%x\n", i, target_subtype_for_arch);
        }

        cpu_subtype_t subtype_to_write = target_subtype_for_arch;
        if (needs_swap) {
            subtype_to_write = OSSwapInt32(subtype_to_write);
        }

        off_t subtype_field_offset = sizeof(struct fat_header) + (i * sizeof(struct fat_arch)) + offsetof(struct fat_arch, cpusubtype);
        if (fseeko(file, subtype_field_offset, SEEK_SET) != 0) {
            printf("Failed to seek to fat_arch cpusubtype field for slice %u: %s\n", i, strerror(errno));
            return false;
        }
        
        if (fwrite(&subtype_to_write, sizeof(cpu_subtype_t), 1, file) != 1) {
            printf("Failed to write updated fat_arch cpusubtype for slice %u\n", i);
            return false;
        }
    }
    
    return true;
}

bool process_fat_file(FILE *file, const char *filepath, bool needs_swap, struct stat *st, const tool_config_t *config) {
    struct fat_header fat_header;
    if (fread(&fat_header, sizeof(fat_header), 1, file) != 1) {
        printf("Can't read fat header from %s\n", filepath);
        return false;
    }
    
    uint32_t nfat_arch = fat_header.nfat_arch;
    if (needs_swap) {
        nfat_arch = OSSwapInt32(nfat_arch);
    }
    
    if (nfat_arch == 0 || nfat_arch > 128) {  // 128 is an arbitrary sanity limit
        printf("Invalid number of architectures in fat file: %u\n", nfat_arch);
        return false;
    }
    
    size_t arch_table_size = nfat_arch * sizeof(struct fat_arch);
    if (sizeof(struct fat_header) + arch_table_size > (size_t)st->st_size) {
        printf("Fat header indicates more architectures than file size can contain\n");
        return false;
    }
    
    struct fat_arch *archs = malloc(arch_table_size);
    if (archs == NULL) {
        printf("Failed to alloc memory for arch entries\n");
        return false;
    }
    
    if (fread(archs, sizeof(struct fat_arch), nfat_arch, file) != nfat_arch) {
        printf("Failed to read fat arch entries from %s\n", filepath);
        free(archs);
        return false;
    }
        
    bool success = true;
    for (uint32_t i = 0; i < nfat_arch; i++) {
        struct fat_arch arch = archs[i];
        if (needs_swap) {
            arch.cputype = OSSwapInt32(arch.cputype);
            arch.cpusubtype = OSSwapInt32(arch.cpusubtype);
            arch.offset = OSSwapInt32(arch.offset);
            arch.size = OSSwapInt32(arch.size);
            arch.align = OSSwapInt32(arch.align);
        }

        if (arch.offset < sizeof(struct fat_header) + arch_table_size ||
            arch.offset + arch.size > (uint32_t)st->st_size) {
            printf("Architecture %u has invalid offset/size bounds. Skipping\n", i);
            continue;
        }

        if (arch.cputype == CPU_TYPE_ARM64) {
            if (!process_arm64_slice(file, filepath, &arch, needs_swap, st->st_size, config)) {
                printf("Failed to process slice %u in %s\n", i, filepath);
                success = false;
                continue;
            }

            if (config->modify_cpu) {
                if (!update_fat_arch_subtype(file, filepath, i, arch.cpusubtype, config->target_subtype, needs_swap, config)) {
                    success = false;
                }
            }
        }
    }
    
    free(archs);
    return success;
}

bool process_file(const char *filepath, const tool_config_t *config) {
    errno = 0;
    FILE *file = fopen(filepath, "r+b");
    if (file == NULL) {
        printf("Cannot open file %s: %s\n", filepath, strerror(errno));
        return false;
    }
    
    struct stat st;
    if (fstat(fileno(file), &st) != 0) {
        printf("Cannot stat file %s: %s\n", filepath, strerror(errno));
        fclose(file);
        return false;
    }

    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, file) != 1) {
        printf("Failed to read magic from %s: %s\n", filepath, strerror(errno));
        fclose(file);
        return false;
    }
    
    bool success = false;
    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        success = process_single_macho(file, filepath, magic, &st, config);
    }
    else if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        bool needs_swap = (magic == FAT_CIGAM);
        success = process_fat_file(file, filepath, needs_swap, &st, config);
    }

    if (fflush(file) != 0 || fclose(file) != 0) {
        printf("Failed to close file %s: %s\n", filepath, strerror(errno));
        return false;
    }

    if (success && (config->modify_cpu || config->modify_platform || config->convert_to_dylib)) {
        printf("Wrote new binary to %s\n", filepath);
    }
    else {
        printf("Failed to process mach-o: %s\n", filepath);
    }

    return success;
}

void process_path(const char *path, const tool_config_t *config) {
    struct stat path_stat;
    if (stat(path, &path_stat) != 0) {
        printf("Cannot stat path %s: %s\n", path, strerror(errno));
        return;
    }

    if (S_ISREG(path_stat.st_mode)) {
        process_file(path, config);
    }
    else if (S_ISDIR(path_stat.st_mode)) {
        if (config->recursive) {
            if (config->verbose) {
                printf("Entering directory: %s\n", path);
            }

            DIR *dir = opendir(path);
            if (dir == NULL) {
                printf("Cannot open directory %s: %s\n", path, strerror(errno));
                return;
            }

            struct dirent *entry = NULL;
            while ((entry = readdir(dir)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, ".fseventsd") == 0) {
                    continue;
                }

                char fullpath[PATH_MAX];
                int written = snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
                if (written < 0 || written >= sizeof(fullpath)) {
                    printf("Path too long, skipping: %s/%s\n", path, entry->d_name);
                    continue;
                }

                process_path(fullpath, config);
            }
            closedir(dir);
        }
    }
}

void print_usage(const char *prog_name) {
    printf("Usage: %s <input_path> [options]\n\n", basename((char *)prog_name));
    printf("Options:\n");
    printf("  -o, --output <path>    Write output to path (default: modify in-place)\n");
    printf("  -h, --help             Show help\n");
    printf("  -r, --recursive        Process directories recursively\n");
    printf("  -v, --verbose          Show detailed output\n\n");
    printf("  --set-cpu <type>       Set ARM64 CPU subtype (arm64, arm64e)\n");
    printf("  --set-platform <name>  Set platform (ios, macos, ios-simulator, etc)\n");
    printf("  --minos <version>      Set min OS version (required with --set-platform)\n");
    printf("  --sdk <version>        Set SDK version (required with --set-platform)\n");
    printf("  --to-dylib             Convert MH_EXECUTE to MH_DYLIB (for dlopen() support)\n\n");
    printf("Example: %s foo.app/foo --set-cpu arm64 --set-platform ios-simulator --minos 14.0 --sdk 15.0\n", basename((char *)prog_name));
}

#ifndef TESTS_RUNNING

int main(int argc, char *argv[]) {
    tool_config_t config = {0};
    config.recursive = false;
    config.modify_cpu = false;
    config.modify_platform = false;
    config.verbose = false;

    const char *set_cpu_str = NULL;
    const char *set_platform_str = NULL;
    const char *minos_str = NULL;
    const char *sdk_str = NULL;

    struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"recursive", no_argument, 0, 'r'},
        {"verbose", no_argument, 0, 'v'},
        {"set-cpu", required_argument, 0, 'c'},
        {"set-platform", required_argument, 0, 'p'},
        {"minos", required_argument, 0, 'm'},
        {"sdk", required_argument, 0, 's'},
        {"output", required_argument, 0, 'o'},
        {"to-dylib", no_argument, 0, 0x1000},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "hrvc:p:m:s:o:", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        case 'r':
            config.recursive = true;
            break;
        case 'v':
            config.verbose = true;
            break;
        case 'c':
            config.modify_cpu = true;
            set_cpu_str = optarg;
            break;
        case 'p':
            config.modify_platform = true;
            set_platform_str = optarg;
            break;
        case 'm':
            minos_str = optarg;
            break;
        case 's':
            sdk_str = optarg;
            break;
        case 'o':
            config.output_path = optarg;
            break;
        case 0x1000:
            config.convert_to_dylib = true;
            break;
        default:
            abort();
        }
    }

    if (optind >= argc) {
        printf("Input path is required\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    config.input_path = argv[optind];

    if (!config.modify_cpu && !config.modify_platform && !config.convert_to_dylib) {
        printf("No action specified. Use --set-cpu, --set-platform, or --to-dylib\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (config.modify_cpu) {
        if (!subtype_name_to_id(set_cpu_str, &config.target_subtype)) {
            printf("Invalid CPU subtype %s. Use arm64 or arm64e\n", set_cpu_str);
            return EXIT_FAILURE;
        }
    }

    if (config.modify_platform) {
        if (!set_platform_str || !minos_str || !sdk_str) {
            printf("Options --set-platform, --minos, and --sdk are all required together\n");
            return EXIT_FAILURE;
        }

        if (!platform_name_to_id(set_platform_str, &config.target_platform)) {
            printf("Invalid platform name %s. See --help for examples\n", set_platform_str);
            return EXIT_FAILURE;
        }

        if (!parse_version(minos_str, &config.target_minos)) {
            printf("Invalid minOS version format %s. Use format like X.Y or X.Y.Z\n", minos_str);
            return EXIT_FAILURE;
        }

        if (!parse_version(sdk_str, &config.target_sdk)) {
            printf("Invalid SDK version format %s. Use format like X.Y or X.Y.Z\n", sdk_str);
            return EXIT_FAILURE;
        }
    }
    else {
        if (minos_str || sdk_str) {
            printf("--minos and --sdk options are ignored without --set-platform\n");
        }
    }
    
    if (config.output_path) {
        FILE *input = fopen(config.input_path, "rb");
        if (input == NULL) {
            printf("Cannot open input file %s: %s\n", config.input_path, strerror(errno));
            return EXIT_FAILURE;

        }
        FILE *output = fopen(config.output_path, "wb");
        if (output == NULL) {
            printf("Cannot open output file %s: %s\n", config.output_path, strerror(errno));
            fclose(input);
            return EXIT_FAILURE;
        }
        
        char buffer[8192];
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), input)) > 0) {
            fwrite(buffer, 1, bytes_read, output);
        }
        
        fclose(input);
        fclose(output);
        
        config.input_path = config.output_path;
    }

    process_path(config.input_path, &config);

    return EXIT_SUCCESS;
}

#endif // TESTS_RUNNING