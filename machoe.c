//
//  machoe.c
//  machoe
//
//  Created by Ethan Arbuckle
//

#include "machoe.h"
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

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

#ifdef TESTS_RUNNING
#define EXPORT_FOR_TESTING
#else
#define EXPORT_FOR_TESTING static
#endif

EXPORT_FOR_TESTING bool perform_framework_normalization(uint8_t *commands, uint32_t ncmds, uint32_t *sizeofcmds_ptr, size_t max_sizeofcmds, uint32_t final_target_platform, bool verbose) {
    uint32_t original_sizeofcmds = *sizeofcmds_ptr;
    uint8_t *new_commands_buffer = malloc(max_sizeofcmds);
    if (new_commands_buffer == NULL) {
        printf("Error: Failed to allocate buffer for framework normalization\n");
        return false;
    }

    uint8_t *read_ptr = commands;
    uint8_t *write_ptr = new_commands_buffer;
    uint32_t current_new_size = 0;
    bool changed = false;

    const char *sys_framework_prefix = "/System/Library/Frameworks/";
    const size_t sys_framework_prefix_len = strlen(sys_framework_prefix);
    const char *versions_a = "Versions/A/";
    const size_t versions_a_len = strlen(versions_a);

    bool target_is_macos = final_target_platform == PLATFORM_MACOS;

    for (uint32_t i = 0; i < ncmds; ++i) {
        struct load_command *lc = (struct load_command *)read_ptr;

        if ((uintptr_t)read_ptr + sizeof(struct load_command) > (uintptr_t)commands + original_sizeofcmds) {
            printf("Error: Command %u header extends beyond sizeofcmds during normalization\n", i);
            free(new_commands_buffer);
            return false;
        }

        if (lc->cmdsize == 0 || (uintptr_t)read_ptr + lc->cmdsize > (uintptr_t)commands + original_sizeofcmds) {
            printf("Error: Command %u (cmd 0x%x) has invalid cmdsize %u during normalization\n", i, lc->cmd, lc->cmdsize);
            free(new_commands_buffer);
            return false;
        }

        bool copy_original = true;
        char new_path[PATH_MAX];
        uint32_t new_cmdsize = lc->cmdsize;

        if (lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB || lc->cmd == LC_REEXPORT_DYLIB) {
            struct dylib_command *dylib_cmd = (struct dylib_command *)lc;
            if (dylib_cmd->dylib.name.offset >= lc->cmdsize) {
                printf("Warning: Command %u (cmd 0x%x) has invalid dylib offset %u >= cmdsize %u. Skipping normalization for this command\n", i, lc->cmd, dylib_cmd->dylib.name.offset, lc->cmdsize);
            }
            else {
                const char *original_path = (const char *)lc + dylib_cmd->dylib.name.offset;
                size_t original_path_len = strnlen(original_path, lc->cmdsize - dylib_cmd->dylib.name.offset);
                if (original_path_len >= lc->cmdsize - dylib_cmd->dylib.name.offset) {
                    printf("Warning: Path string for command %u (cmd 0x%x) potentially not null-terminated within cmdsize. Skipping normalization\n", i, lc->cmd);
                }
                else if (strncmp(original_path, sys_framework_prefix, sys_framework_prefix_len) == 0) {
                    const char *framework_part = original_path + sys_framework_prefix_len;
                    const char *framework_suffix = strstr(framework_part, ".framework/");

                    if (framework_suffix) {
                        size_t framework_name_len = framework_suffix - framework_part + strlen(".framework");
                        const char *binary_name_part = framework_suffix + strlen(".framework/");

                        const char *current_binary_name = binary_name_part;
                        bool has_versions_a = false;
                        if (strncmp(binary_name_part, versions_a, versions_a_len) == 0) {
                            current_binary_name = binary_name_part + versions_a_len;
                            has_versions_a = true;
                        }

                        if (target_is_macos && !has_versions_a) {
                            snprintf(new_path, PATH_MAX, "%.*s/Versions/A/%s", (int)(sys_framework_prefix_len + framework_name_len), original_path, current_binary_name);
                            copy_original = false;
                            if (verbose) {
                                printf("Normalizing fw path (add): %s -> %s\n", original_path, new_path);
                            }
                        }
                        else if (!target_is_macos && has_versions_a) {
                            snprintf(new_path, PATH_MAX, "%.*s/%s", (int)(sys_framework_prefix_len + framework_name_len), original_path, current_binary_name);
                            copy_original = false;
                            if (verbose) {
                                printf("Normalizing fw path (rem): %s -> %s\n", original_path, new_path);
                            }
                        }
                    }
                }
            }
        }

        if (!copy_original) {
            size_t new_path_len = strlen(new_path) + 1;
            new_cmdsize = (uint32_t)((sizeof(struct dylib_command) + new_path_len + 7) & ~7);
            if (current_new_size + new_cmdsize > max_sizeofcmds) {
                printf("Error: Normalizing framework path would exceed maximum command size. Failed path: %s\n", new_path);
                free(new_commands_buffer);
                return false;
            }

            struct dylib_command *new_dylib_cmd = (struct dylib_command *)write_ptr;
            memcpy(new_dylib_cmd, lc, sizeof(struct dylib_command));
            new_dylib_cmd->cmdsize = new_cmdsize;
            new_dylib_cmd->dylib.name.offset = sizeof(struct dylib_command);

            memcpy((uint8_t *)new_dylib_cmd + sizeof(struct dylib_command), new_path, new_path_len);

            size_t used_size = sizeof(struct dylib_command) + new_path_len;
            if (new_cmdsize > used_size) {
                memset((uint8_t *)new_dylib_cmd + used_size, 0, new_cmdsize - used_size);
            }

            write_ptr += new_cmdsize;
            current_new_size += new_cmdsize;
            changed = true;
        }
        else {
            if (current_new_size + lc->cmdsize > max_sizeofcmds) {
                printf("Error: Copying original command %u exceeds maximum command size during normalization\n", i);
                free(new_commands_buffer);
                return false;
            }

            memcpy(write_ptr, read_ptr, lc->cmdsize);
            write_ptr += lc->cmdsize;
            current_new_size += lc->cmdsize;
        }

        read_ptr += lc->cmdsize;
    }

    if (changed) {
        if (verbose) {
            printf("Framework paths normalized. Old size: %u, New size: %u\n", original_sizeofcmds, current_new_size);
        }

        memcpy(commands, new_commands_buffer, current_new_size);
        *sizeofcmds_ptr = current_new_size;
    }

    free(new_commands_buffer);
    return true;
}

EXPORT_FOR_TESTING bool remove_lc_main(uint8_t *commands, uint32_t ncmds, uint32_t *sizeofcmds) {
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

EXPORT_FOR_TESTING void patch_pagezero(uint8_t *commands, uint32_t ncmds) {
    uint8_t *p = commands;
    for (uint32_t i = 0; i < ncmds; i++) {
        struct load_command *lc = (struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)p;
            if (strcmp(seg->segname, "__PAGEZERO") == 0) {
                strncpy(seg->segname, "__dylibolical", sizeof(seg->segname));
                seg->vmsize = 0x4000;
                seg->vmaddr = 0;
            }
        }

        p += lc->cmdsize;
    }
}

EXPORT_FOR_TESTING bool add_lc_id_dylib(uint8_t *commands, uint32_t *ncmds, uint32_t *sizeofcmds, size_t maxcmdsize, const char *dylib_path) {
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

EXPORT_FOR_TESTING bool rpath_exists(uint8_t *commands, uint32_t ncmds, uint32_t sizeofcmds, const char *rpath_value) {
    if (commands == NULL || rpath_value == NULL) {
        return false;
    }

    uint8_t *p = commands;
    uint8_t *end = commands + sizeofcmds;

    for (uint32_t i = 0; i < ncmds; i++) {
        if (p + sizeof(struct load_command) > end) {
            break;
        }

        struct load_command *lc = (struct load_command *)p;
        if (lc->cmdsize == 0 || p + lc->cmdsize > end) {
            break;
        }

        if (lc->cmd == LC_RPATH) {
            if (lc->cmdsize >= sizeof(struct rpath_command)) {
                struct rpath_command *rc = (struct rpath_command *)lc;
                if (rc->path.offset < lc->cmdsize) {
                    const char *existing = (const char *)((uint8_t *)rc + rc->path.offset);

                    size_t max_len = lc->cmdsize - rc->path.offset;
                    size_t existing_len = strnlen(existing, max_len);
                    if (existing_len < max_len) {
                        if (strcmp(existing, rpath_value) == 0) {
                            return true;
                        }
                    }
                }
            }
        }

        p += lc->cmdsize;
    }

    return false;
}

EXPORT_FOR_TESTING bool add_lc_rpath(uint8_t *commands, uint32_t *ncmds, uint32_t *sizeofcmds, size_t maxcmdsize, const char *rpath_value) {
    if (commands == NULL || ncmds == NULL || sizeofcmds == NULL || rpath_value == NULL) {
        return false;
    }

    if (rpath_value[0] == '\0') {
        return false;
    }

    if (rpath_exists(commands, *ncmds, *sizeofcmds, rpath_value)) {
        return true;
    }

    size_t path_len = strlen(rpath_value) + 1;
    uint32_t padded_size = (uint32_t)((sizeof(struct rpath_command) + path_len + 7) & ~7);

    if (*sizeofcmds + padded_size > maxcmdsize) {
        return false;
    }

    struct rpath_command *rc = (struct rpath_command *)(commands + *sizeofcmds);
    memset(rc, 0, padded_size);

    rc->cmd = LC_RPATH;
    rc->cmdsize = padded_size;
    rc->path.offset = sizeof(struct rpath_command);

    memcpy((uint8_t *)rc + sizeof(struct rpath_command), rpath_value, path_len);

    *ncmds = *ncmds + 1;
    *sizeofcmds = *sizeofcmds + padded_size;
    return true;
}

EXPORT_FOR_TESTING void transform_executable_to_dylib(void *mapped, size_t filesize, const char *basename) {
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
        *id_out = CPU_SUBTYPE_LIB64 | CPU_SUBTYPE_ARM64E;
        return true;
    }

    return false;
}

const char *subtype_id_to_name(cpu_subtype_t id) {
    cpu_subtype_t base_id = id & ~CPU_SUBTYPE_MASK;
    if (base_id == CPU_SUBTYPE_ARM64E || base_id == (CPU_SUBTYPE_LIB64 | CPU_SUBTYPE_ARM64E)) {
        return "arm64e";
    }
    else if (base_id == CPU_SUBTYPE_ARM64_ALL) {
        return "arm64";
    }

    return "Unknown Subtype";
}

static bool process_macho_slice(FILE *file, off_t slice_offset, size_t slice_size, const tool_config_t *config) {
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
    bool header_needs_update = false;
    uint32_t original_platform = 0;
    uint32_t final_target_platform = 0;
    bool need_original_platform = config->normalize_frameworks && !config->modify_platform;

    uint8_t *commands_buffer = NULL;
    size_t commands_buffer_alloc_size = 0;
    bool read_commands_needed = config->modify_platform || config->normalize_frameworks || config->convert_to_dylib || (config->add_rpath != NULL && config->add_rpath[0] != '\0');
    if (read_commands_needed) {
        commands_buffer_alloc_size = header.sizeofcmds + 512;
        if (commands_buffer_alloc_size > slice_size - sizeof(header)) {
            commands_buffer_alloc_size = slice_size - sizeof(header);
        }

        if (header.sizeofcmds > commands_buffer_alloc_size) {
            printf("Error: sizeofcmds (%u) exceeds calculated max command buffer size (%zu)\n", header.sizeofcmds, commands_buffer_alloc_size);
            return false;
        }

        commands_buffer = malloc(commands_buffer_alloc_size);
        if (commands_buffer == NULL) {
            printf("Failed to allocate memory for load commands buffer\n");
            return false;
        }

        off_t commands_offset = slice_offset + sizeof(struct mach_header_64);
        if (fseeko(file, commands_offset, SEEK_SET) != 0) {
            printf("Failed to seek to load commands at offset %lld: %s\n", (long long)commands_offset, strerror(errno));
            free(commands_buffer);
            return false;
        }

        if (fread(commands_buffer, header.sizeofcmds, 1, file) != 1) {
            printf("Failed to read load commands (size %u) at offset %lld\n", header.sizeofcmds, (long long)commands_offset);
            free(commands_buffer);
            return false;
        }

        if (need_original_platform) {
            uint8_t *p = commands_buffer;
            for (uint32_t i = 0; i < header.ncmds; ++i) {
                struct load_command *lc = (struct load_command *)p;
                if (lc->cmd == LC_BUILD_VERSION) {
                    if (lc->cmdsize >= sizeof(struct build_version_command)) {
                        struct build_version_command *bvc = (struct build_version_command *)lc;
                        original_platform = bvc->platform;
                    }
                    else {
                        printf("Warning: Found LC_BUILD_VERSION with invalid size (%u), cannot determine original platform reliably\n", lc->cmdsize);
                    }

                    break;
                }

                if (lc->cmdsize == 0 || p + lc->cmdsize > commands_buffer + header.sizeofcmds) {
                    break;
                }

                p += lc->cmdsize;
            }

            if (original_platform == 0) {
                printf("Warning: Could not find LC_BUILD_VERSION to determine original platform for normalization\n");
                need_original_platform = false;
            }
        }
    }

    if (config->modify_platform) {
        final_target_platform = config->target_platform;
    }
    else if (config->normalize_frameworks && original_platform != 0) {
        final_target_platform = original_platform;
    }
    else {
        final_target_platform = original_platform;
    }

    if (config->convert_to_dylib && header.filetype == MH_EXECUTE) {
        int fd = fileno(file);
        void *mapped = mmap(NULL, slice_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, slice_offset);
        if (mapped == MAP_FAILED) {
            printf("Failed to mmap slice at offset %lld for dylib conversion: %s\n", (long long)slice_offset, strerror(errno));
            if (commands_buffer) {
                free(commands_buffer);
            }

            return false;
        }

        const char *base = basename((char *)config->input_path);
        transform_executable_to_dylib(mapped, slice_size, base);
        if (msync(mapped, slice_size, MS_SYNC) == -1) {
            printf("Warning: msync failed after dylib conversion: %s\n", strerror(errno));
        }

        munmap(mapped, slice_size);
        modified = true;
        header_needs_update = true;

        if (config->verbose) {
            printf("Converted slice at offset %lld to MH_DYLIB\n", (long long)slice_offset);
        }

        if (fseeko(file, slice_offset, SEEK_SET) != 0 || fread(&header, sizeof(header), 1, file) != 1) {
            printf("Failed to reread header after dylib transform\n");
            if (commands_buffer) {
                free(commands_buffer);
            }

            return false;
        }

        if (commands_buffer) {
            off_t commands_offset = slice_offset + sizeof(struct mach_header_64);
            if (fseeko(file, commands_offset, SEEK_SET) != 0) {
                free(commands_buffer);
                return false;
            }

            if (header.sizeofcmds > commands_buffer_alloc_size) {
                printf("Error: sizeofcmds (%u) after dylib conversion exceeds allocated buffer (%zu)\n", header.sizeofcmds, commands_buffer_alloc_size);
                free(commands_buffer);
                return false;
            }

            if (fread(commands_buffer, header.sizeofcmds, 1, file) != 1) {
                free(commands_buffer);
                return false;
            }
        }
    }

    if (config->modify_cpu) {
        cpu_subtype_t current_subtype = header.cpusubtype;
        cpu_subtype_t current_base_subtype = current_subtype & ~CPU_SUBTYPE_LIB64;
        cpu_subtype_t target_base_subtype = config->target_subtype & ~CPU_SUBTYPE_LIB64;

        if (current_base_subtype != target_base_subtype) {
            if (config->verbose) {
                printf("Slice at offset %lld: Changing CPU subtype from %s (0x%x) to %s (0x%x)\n", (long long)slice_offset, subtype_id_to_name(current_subtype), current_subtype, subtype_id_to_name(config->target_subtype), config->target_subtype);
            }

            header.cpusubtype = config->target_subtype | (current_subtype & CPU_SUBTYPE_LIB64);
            modified = true;
            header_needs_update = true;
        }
    }

    if (config->modify_platform) {
        bool build_version_found = false;
        uint8_t *p = commands_buffer;

        for (uint32_t i = 0; i < header.ncmds; ++i) {
            struct load_command *lc = (struct load_command *)p;
            if (!lc || lc->cmdsize == 0 || p + lc->cmdsize > commands_buffer + header.sizeofcmds) {
                printf("Error: Invalid load command structure encountered during platform modification\n");
                free(commands_buffer);
                return false;
            }

            if (lc->cmd == LC_BUILD_VERSION) {
                if (lc->cmdsize < sizeof(struct build_version_command)) {
                    printf("Warning: LC_BUILD_VERSION command too small at index %u (size: %u). Skipping modification\n", i, lc->cmdsize);
                    build_version_found = true;
                    break;
                }

                struct build_version_command *bvc = (struct build_version_command *)lc;
                if (bvc->platform != config->target_platform || bvc->minos != config->target_minos || bvc->sdk != config->target_sdk) {
                    if (config->verbose) {
                        printf("Slice at offset %lld: Modifying LC_BUILD_VERSION: platform %s (0x%x) -> %s (0x%x), minos 0x%x -> 0x%x, sdk 0x%x -> 0x%x\n", (long long)slice_offset, platform_id_to_name(bvc->platform), bvc->platform, platform_id_to_name(config->target_platform), config->target_platform, bvc->minos, config->target_minos, bvc->sdk, config->target_sdk);
                    }

                    bvc->platform = config->target_platform;
                    bvc->minos = config->target_minos;
                    bvc->sdk = config->target_sdk;
                    modified = true;
                }

                build_version_found = true;
                break;
            }
            p += lc->cmdsize;
        }

        p = commands_buffer;
        for (int i = 0; i < header.ncmds; ++i) {
            struct load_command *lc = (struct load_command *)p;
            if (lc->cmd == LC_VERSION_MIN_IPHONEOS || lc->cmd == LC_VERSION_MIN_MACOSX) {
                if (config->verbose) {
                    printf("Slice at offset %lld: Removing LC_VERSION_MIN command: cmd=0x%x, cmdsize=%u\n", (long long)slice_offset, lc->cmd, lc->cmdsize);
                }

                memmove(p, p + lc->cmdsize, commands_buffer + header.sizeofcmds - p - lc->cmdsize);
                header.sizeofcmds -= lc->cmdsize;
                header.ncmds--;
                modified = true;
                header_needs_update = true;
                break;
            }
            p += lc->cmdsize;
        }

        if (!build_version_found) {
            uint32_t end_of_cmds_offset_in_buffer = header.sizeofcmds;
            uint32_t new_cmd_size = sizeof(struct build_version_command);
            if (end_of_cmds_offset_in_buffer + new_cmd_size > commands_buffer_alloc_size) {
                printf("Slice at offset %lld: Not enough space in command buffer to add LC_BUILD_VERSION command\n", (long long)slice_offset);
                free(commands_buffer);
                return false;
            }

            if (config->verbose) {
                printf("Slice at offset %lld: LC_BUILD_VERSION not found. Adding new command: platform %s (0x%x), minos 0x%x, sdk 0x%x\n", (long long)slice_offset, platform_id_to_name(config->target_platform), config->target_platform, config->target_minos, config->target_sdk);
            }

            struct build_version_command *new_bvc = (struct build_version_command *)(commands_buffer + end_of_cmds_offset_in_buffer);
            new_bvc->cmd = LC_BUILD_VERSION;
            new_bvc->cmdsize = new_cmd_size;
            new_bvc->platform = config->target_platform;
            new_bvc->minos = config->target_minos;
            new_bvc->sdk = config->target_sdk;
            new_bvc->ntools = 0;

            header.ncmds++;
            header.sizeofcmds += new_cmd_size;
            modified = true;
            header_needs_update = true;
        }
    }

    if (commands_buffer && (config->normalize_frameworks || config->modify_platform)) {
        uint32_t sizeofcmds_before_norm = header.sizeofcmds;
        size_t max_lc_size = commands_buffer_alloc_size;

        if (perform_framework_normalization(commands_buffer, header.ncmds, &header.sizeofcmds, max_lc_size, final_target_platform, config->verbose)) {
            if (header.sizeofcmds != sizeofcmds_before_norm) {
                modified = true;
                header_needs_update = true;
            }
        }
        else {
            printf("Framework normalization failed for slice at offset %lld\n", (long long)slice_offset);
            free(commands_buffer);
            return false;
        }
    }

    if (commands_buffer && config->add_rpath != NULL && config->add_rpath[0] != '\0') {
        if (!add_lc_rpath(commands_buffer, &header.ncmds, &header.sizeofcmds, commands_buffer_alloc_size, config->add_rpath)) {
            printf("Slice at offset %lld: Not enough room to add LC_RPATH (%s)\n", (long long)slice_offset, config->add_rpath);
            free(commands_buffer);
            return false;
        }

        modified = true;
        header_needs_update = true;

        if (config->verbose) {
            printf("Slice at offset %lld: Added LC_RPATH: %s\n", (long long)slice_offset, config->add_rpath);
        }
    }

    if (commands_buffer && modified) {
        off_t commands_offset = slice_offset + sizeof(struct mach_header_64);
        if (fseeko(file, commands_offset, SEEK_SET) != 0) {
            printf("Failed to seek to command offset %lld for writing: %s\n", (long long)commands_offset, strerror(errno));
            free(commands_buffer);
            return false;
        }

        if (fwrite(commands_buffer, header.sizeofcmds, 1, file) != 1) {
            printf("Failed to write modified load commands (size %u) at offset %lld\n", header.sizeofcmds, (long long)commands_offset);
            free(commands_buffer);
            return false;
        }
    }

    if (commands_buffer) {
        free(commands_buffer);
        commands_buffer = NULL;
    }

    if (header_needs_update) {
        if (fseeko(file, slice_offset, SEEK_SET) != 0) {
            printf("Failed to seek to slice start (%lld) to write updated header: %s\n", (long long)slice_offset, strerror(errno));
            return false;
        }

        if (fwrite(&header, sizeof(header), 1, file) != 1) {
            printf("Failed to write updated mach_header_64 at offset %lld\n", (long long)slice_offset);
            return false;
        }

        if (config->verbose) {
            printf("Slice at offset %lld: Header updated successfully (ncmds=%u, sizeofcmds=%u, subtype=0x%x)\n", (long long)slice_offset, header.ncmds, header.sizeofcmds, header.cpusubtype);
        }
    }
    else if (modified && config->verbose) {
        printf("Slice at offset %lld: Load command content updated\n", (long long)slice_offset);
    }

    return true;
}


static bool process_single_macho(FILE *file, const char *filepath, uint32_t magic, struct stat *st, const tool_config_t *config) {
    if (magic == MH_CIGAM_64) {
        printf("Wrong endianness MH_CIGAM_64 in %s\n", filepath);
        return false;
    }
    else {
        return process_macho_slice(file, 0, st->st_size, config);
    }
}

static bool process_arm64_slice(FILE *file, const char *filepath, struct fat_arch *arch_host_order, bool needs_swap_for_write_operations, size_t file_size, const tool_config_t *config) {
    uint32_t slice_cpusubtype = arch_host_order->cpusubtype;
    uint32_t slice_offset = arch_host_order->offset;
    uint32_t slice_size = arch_host_order->size;

    if (config->verbose) {
        printf("ARM64 slice (subtype 0x%x) at offset %u, size %u\n", slice_cpusubtype, slice_offset, slice_size);
    }

    if (slice_offset == 0 || slice_offset + slice_size > file_size || slice_size < sizeof(struct mach_header_64)) {
        printf("Invalid offset/size for fat arch (offset %u, size %u, file_size %zu) in %s. Skipping slice\n", slice_offset, slice_size, file_size, filepath);
        return false;
    }

    return process_macho_slice(file, (off_t)arch_host_order->offset, (size_t)arch_host_order->size, config);
}

static bool update_fat_arch_subtype(FILE *file, const char *filepath, uint32_t i, cpu_subtype_t current_subtype, cpu_subtype_t target_subtype, bool needs_swap, const tool_config_t *config) {
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
    fseeko(file, 0, SEEK_SET);
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

bool process_binary(const char *filepath, const tool_config_t *config) {
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

    bool is_macho = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) || (magic == FAT_MAGIC || magic == FAT_CIGAM);
    if (!is_macho) {
        if (config->verbose) {
            printf("Skipping non-mach-o file: %s\n", filepath);
        }

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

    if (success && (config->modify_cpu || config->modify_platform || config->convert_to_dylib || (config->add_rpath != NULL && config->add_rpath[0] != '\0'))) {
        printf("Wrote new binary to %s\n", filepath);
    }
    else {
        printf("Failed to process mach-o: %s\n", filepath);
    }

    return success;
}

void process_binaries_in_directory(const char *path, const tool_config_t *config) {
    struct stat path_stat;
    if (stat(path, &path_stat) != 0) {
        printf("Cannot stat path %s: %s\n", path, strerror(errno));
        return;
    }

    if (S_ISREG(path_stat.st_mode)) {
        process_binary(path, config);
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

                process_binaries_in_directory(fullpath, config);
            }
            closedir(dir);
        }
    }
}
