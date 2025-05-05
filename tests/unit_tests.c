#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TESTS_RUNNING 1

#include "../main.c"

void print_test_header(const char* test_name) {
    printf("--- Running test: %s ---\n", test_name);
}

void print_test_footer(const char* test_name, bool success) {
    printf("--- Test %s: %s ---\n\n", test_name, success ? "PASSED" : "FAILED");
}

void test_parse_version() {
    print_test_header("parse_version");
    bool success = true;
    uint32_t version;

    assert(parse_version("1.2.3", &version) && version == 0x00010203);
    assert(parse_version("10.5", &version) && version == 0x000a0500);
    assert(parse_version("14.0.1", &version) && version == 0x000e0001);
    assert(parse_version("65535.255.255", &version) && version == 0xffffFFFF);

    assert(!parse_version("1", &version));
    assert(!parse_version("1.", &version));
    assert(!parse_version("a.b.c", &version));

    assert(!parse_version("65536.0.0", &version));
    assert(!parse_version("1.256.0", &version));
    assert(!parse_version("1.0.256", &version));

    print_test_footer("parse_version", success);
}

void test_platform_name_to_id() {
    print_test_header("platform_name_to_id");
    bool success = true;
    uint32_t id;

    assert(platform_name_to_id("macos", &id) && id == PLATFORM_MACOS);
    assert(platform_name_to_id("iOS", &id) && id == PLATFORM_IOS);
    assert(platform_name_to_id("ios-simulator", &id) && id == PLATFORM_IOSSIMULATOR);

    assert(!platform_name_to_id("invalidos", &id));
    assert(!platform_name_to_id(NULL, &id));
    assert(!platform_name_to_id("macos", NULL));

    print_test_footer("platform_name_to_id", success);
}

void test_platform_id_to_name() {
    print_test_header("platform_id_to_name");
    bool success = true;

    assert(strcmp(platform_id_to_name(PLATFORM_MACOS), "macOS") == 0);
    assert(strcmp(platform_id_to_name(PLATFORM_IOS), "iOS") == 0);
    assert(strcmp(platform_id_to_name(PLATFORM_IOSSIMULATOR), "iOS Simulator") == 0);
    assert(strcmp(platform_id_to_name(999), "Unknown") == 0);

    print_test_footer("platform_id_to_name", success);
}

void test_subtype_name_to_id() {
    print_test_header("subtype_name_to_id");
    bool success = true;
    cpu_subtype_t id;

    assert(subtype_name_to_id("arm64", &id) && id == CPU_SUBTYPE_ARM64_ALL);
    assert(subtype_name_to_id("ARM64E", &id) && id == CPU_SUBTYPE_ARM64E);
    assert(!subtype_name_to_id("armv7", &id));
    assert(!subtype_name_to_id(NULL, &id));
    assert(!subtype_name_to_id("arm64", NULL));

    print_test_footer("subtype_name_to_id", success);
}

void test_subtype_id_to_name() {
    print_test_header("subtype_id_to_name");
    bool success = true;

    assert(strcmp(subtype_id_to_name(CPU_SUBTYPE_ARM64_ALL), "arm64") == 0);
    assert(strcmp(subtype_id_to_name(CPU_SUBTYPE_ARM64E), "arm64e") == 0);
    assert(strcmp(subtype_id_to_name(CPU_SUBTYPE_ARM64_ALL | CPU_SUBTYPE_LIB64), "arm64") == 0);
    assert(strcmp(subtype_id_to_name(CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_LIB64), "arm64e") == 0);
    assert(strcmp(subtype_id_to_name(5), "Unknown Subtype") == 0);

    print_test_footer("subtype_id_to_name", success);
}

void test_remove_lc_main() {
    print_test_header("remove_lc_main");
    bool success = true;
    uint8_t buffer[512];
    uint32_t ncmds;
    uint32_t sizeofcmds;

    memset(buffer, 0, sizeof(buffer));
    struct load_command *lc1 = (struct load_command *)buffer;
    lc1->cmd = LC_SEGMENT_64;
    lc1->cmdsize = sizeof(struct segment_command_64);

    struct entry_point_command *lc_main = (struct entry_point_command *)(buffer + lc1->cmdsize);
    lc_main->cmd = LC_MAIN;
    lc_main->cmdsize = sizeof(struct entry_point_command);

    struct load_command *lc3 = (struct load_command *)(buffer + lc1->cmdsize + lc_main->cmdsize);
    lc3->cmd = LC_ID_DYLIB;
    lc3->cmdsize = sizeof(struct dylib_command);

    ncmds = 3;
    sizeofcmds = lc1->cmdsize + lc_main->cmdsize + lc3->cmdsize;
    uint32_t original_sizeofcmds = sizeofcmds;
    assert(remove_lc_main(buffer, ncmds, &sizeofcmds));
    assert(sizeofcmds == original_sizeofcmds - lc_main->cmdsize);

    struct load_command *lc_check1 = (struct load_command *)buffer;
    struct load_command *lc_check2 = (struct load_command *)(buffer + lc_check1->cmdsize);
    assert(lc_check1->cmd == LC_SEGMENT_64);
    assert(lc_check2->cmd == LC_ID_DYLIB);

    // Case 2: LC_MAIN does not exist
    memset(buffer, 0, sizeof(buffer));
    lc1 = (struct load_command *)buffer;
    lc1->cmd = LC_SEGMENT_64;
    lc1->cmdsize = sizeof(struct segment_command_64);
    lc3 = (struct load_command *)(buffer + lc1->cmdsize);
    lc3->cmd = LC_ID_DYLIB;
    lc3->cmdsize = sizeof(struct dylib_command);

    ncmds = 2;
    sizeofcmds = lc1->cmdsize + lc3->cmdsize;
    original_sizeofcmds = sizeofcmds;
    assert(!remove_lc_main(buffer, ncmds, &sizeofcmds));
    assert(sizeofcmds == original_sizeofcmds);

    lc_check1 = (struct load_command *)buffer;
    lc_check2 = (struct load_command *)(buffer + lc_check1->cmdsize);
    assert(lc_check1->cmd == LC_SEGMENT_64);
    assert(lc_check2->cmd == LC_ID_DYLIB);

    // Case 3: LC_MAIN is the only command
    memset(buffer, 0, sizeof(buffer));
    lc_main = (struct entry_point_command *)buffer;
    lc_main->cmd = LC_MAIN;
    lc_main->cmdsize = sizeof(struct entry_point_command);
    ncmds = 1;
    sizeofcmds = lc_main->cmdsize;
    original_sizeofcmds = sizeofcmds;
    assert(remove_lc_main(buffer, ncmds, &sizeofcmds));
    assert(sizeofcmds == 0);

    print_test_footer("remove_lc_main", success);
}

void test_patch_pagezero() {
    print_test_header("patch_pagezero");
    bool success = true;
    uint8_t buffer[512];
    uint32_t ncmds;

    // Case 1: __PAGEZERO exists
    memset(buffer, 0, sizeof(buffer));
    struct segment_command_64 *seg_pagezero = (struct segment_command_64 *)buffer;
    seg_pagezero->cmd = LC_SEGMENT_64;
    seg_pagezero->cmdsize = sizeof(struct segment_command_64);
    strcpy(seg_pagezero->segname, "__PAGEZERO");
    seg_pagezero->vmaddr = 0x100000000;
    seg_pagezero->vmsize = 0x100000000;

    struct load_command *lc2 = (struct load_command *)(buffer + seg_pagezero->cmdsize);
    lc2->cmd = LC_ID_DYLIB;
    lc2->cmdsize = sizeof(struct dylib_command);

    ncmds = 2;
    uint64_t original_vmaddr = seg_pagezero->vmaddr;
    patch_pagezero(buffer, ncmds);

    assert(strcmp(seg_pagezero->segname, "__dylibolical") == 0);
    assert(seg_pagezero->vmsize == 0x4000);
    assert(seg_pagezero->vmaddr == original_vmaddr - 0x4000);

    // Case 2: __PAGEZERO does not exist
    memset(buffer, 0, sizeof(buffer));
    struct segment_command_64 *seg_text = (struct segment_command_64 *)buffer;
    seg_text->cmd = LC_SEGMENT_64;
    seg_text->cmdsize = sizeof(struct segment_command_64);
    strcpy(seg_text->segname, "__TEXT");
    seg_text->vmaddr = 0x100004000;
    seg_text->vmsize = 0x10000;
    uint64_t original_text_vmaddr = seg_text->vmaddr;
    uint64_t original_text_vmsize = seg_text->vmsize;

    lc2 = (struct load_command *)(buffer + seg_text->cmdsize);
    lc2->cmd = LC_ID_DYLIB;
    lc2->cmdsize = sizeof(struct dylib_command);

    ncmds = 2;
    patch_pagezero(buffer, ncmds);

    assert(strcmp(seg_text->segname, "__TEXT") == 0);
    assert(seg_text->vmsize == original_text_vmsize);
    assert(seg_text->vmaddr == original_text_vmaddr);

    print_test_footer("patch_pagezero", success);
}

void test_add_lc_id_dylib() {
    print_test_header("add_lc_id_dylib");
    bool success = true;
    uint8_t buffer[512];
    uint32_t ncmds;
    uint32_t sizeofcmds;
    size_t maxcmdsize = sizeof(buffer);
    const char* dylib_path = "@rpath/MyTest.dylib";
    size_t name_len = strlen(dylib_path) + 1;
    uint32_t expected_cmdsize = (sizeof(struct dylib_command) + name_len + 7) & ~7;

    // Case 1: Enough space
    memset(buffer, 0, sizeof(buffer));
    struct load_command *lc1 = (struct load_command *)buffer;
    lc1->cmd = LC_SEGMENT_64;
    lc1->cmdsize = sizeof(struct segment_command_64);

    ncmds = 1;
    sizeofcmds = lc1->cmdsize;
    uint32_t original_ncmds = ncmds;
    uint32_t original_sizeofcmds = sizeofcmds;

    assert(add_lc_id_dylib(buffer, &ncmds, &sizeofcmds, maxcmdsize, dylib_path));
    assert(ncmds == original_ncmds + 1);
    assert(sizeofcmds == original_sizeofcmds + expected_cmdsize);

    struct dylib_command *added_cmd = (struct dylib_command *)(buffer + original_sizeofcmds);
    assert(added_cmd->cmd == LC_ID_DYLIB);
    assert(added_cmd->cmdsize == expected_cmdsize);
    assert(added_cmd->dylib.name.offset == sizeof(struct dylib_command));
    assert(added_cmd->dylib.timestamp == 1);
    assert(added_cmd->dylib.current_version == 0x10000);
    assert(added_cmd->dylib.compatibility_version == 0x10000);
    assert(strcmp((char *)added_cmd + sizeof(struct dylib_command), dylib_path) == 0);

    // Case 2: Not enough space
    memset(buffer, 0, sizeof(buffer));
    ncmds = 0;
    sizeofcmds = 0;
    maxcmdsize = 10; // Clearly not enough space

    assert(!add_lc_id_dylib(buffer, &ncmds, &sizeofcmds, maxcmdsize, dylib_path));
    assert(ncmds == 0);
    assert(sizeofcmds == 0);

    print_test_footer("add_lc_id_dylib", success);
}

void test_transform_executable_to_dylib() {
    print_test_header("transform_executable_to_dylib");
    bool success = true;

    size_t buffer_size = 2048;
    uint8_t *mapped_buffer = malloc(buffer_size);
    assert(mapped_buffer);
    memset(mapped_buffer, 0, buffer_size);

    struct mach_header_64 *header = (struct mach_header_64 *)mapped_buffer;
    uint8_t *commands = (uint8_t *)(header + 1);

    // Initial state: Executable with LC_MAIN and __PAGEZERO
    header->magic = MH_MAGIC_64;
    header->cputype = CPU_TYPE_ARM64;
    header->cpusubtype = CPU_SUBTYPE_ARM64_ALL;
    header->filetype = MH_EXECUTE;
    header->flags = MH_PIE;
    header->ncmds = 0;
    header->sizeofcmds = 0;

    // Add __PAGEZERO
    struct segment_command_64 *seg_pagezero = (struct segment_command_64 *)commands;
    seg_pagezero->cmd = LC_SEGMENT_64;
    seg_pagezero->cmdsize = sizeof(*seg_pagezero);
    strcpy(seg_pagezero->segname, "__PAGEZERO");
    seg_pagezero->vmaddr = 0x100000000;
    seg_pagezero->vmsize = 0x100000000;
    header->ncmds++;
    header->sizeofcmds += seg_pagezero->cmdsize;

    // Add LC_MAIN
    struct entry_point_command *lc_main = (struct entry_point_command *)(commands + header->sizeofcmds);
    lc_main->cmd = LC_MAIN;
    lc_main->cmdsize = sizeof(*lc_main);
    header->ncmds++;
    header->sizeofcmds += lc_main->cmdsize;

    struct load_command *lc_other = (struct load_command *)(commands + header->sizeofcmds);
    lc_other->cmd = LC_BUILD_VERSION;
    lc_other->cmdsize = 32;
    header->ncmds++;
    header->sizeofcmds += lc_other->cmdsize;

    uint32_t initial_ncmds = header->ncmds;
    uint32_t initial_sizeofcmds = header->sizeofcmds;
    const char *basename = "MyTestApp";

    transform_executable_to_dylib(mapped_buffer, buffer_size, basename);

    assert(header->filetype == MH_DYLIB);
    assert((header->flags & MH_PIE) == 0);

    size_t id_dylib_name_len = strlen("@rpath/MyTestApp.dylib") + 1;
    uint32_t id_dylib_padded_size = (sizeof(struct dylib_command) + id_dylib_name_len + 7) & ~7;
    uint32_t expected_sizeofcmds = initial_sizeofcmds - sizeof(*lc_main) + id_dylib_padded_size;
    uint32_t expected_ncmds = initial_ncmds - 1 + 1;
    assert(header->ncmds == expected_ncmds);
    assert(header->sizeofcmds == expected_sizeofcmds);

    uint8_t *p = commands;
    bool pagezero_found_modified = false;
    bool lc_main_gone = true;
    bool lc_id_dylib_found = false;
    bool lc_other_found = false;

    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command *lc = (struct load_command *)p;
        assert(lc->cmdsize > 0 && (p - commands + lc->cmdsize <= header->sizeofcmds));

        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__dylibolical") == 0) {
                 assert(seg->vmsize == 0x4000);
                 pagezero_found_modified = true;
            }
        }
        else if (lc->cmd == LC_MAIN) {
            lc_main_gone = false;
        }
        else if (lc->cmd == LC_ID_DYLIB) {
            struct dylib_command *idcmd = (struct dylib_command*)lc;
            assert(idcmd->cmdsize == id_dylib_padded_size);
            assert(strcmp((char*)idcmd + sizeof(*idcmd), "@rpath/MyTestApp.dylib") == 0);
            lc_id_dylib_found = true;
        }
        else if (lc->cmd == LC_BUILD_VERSION) {
            lc_other_found = true;
        }

        p += lc->cmdsize;
    }

    assert(pagezero_found_modified);
    assert(lc_main_gone);
    assert(lc_id_dylib_found);
    assert(lc_other_found);

    free(mapped_buffer);
    print_test_footer("transform_executable_to_dylib", success);
}

int main(int argc, char *argv[]) {
    printf("Starting tests...\n\n");

    test_parse_version();
    test_platform_name_to_id();
    test_platform_id_to_name();
    test_subtype_name_to_id();
    test_subtype_id_to_name();
    test_remove_lc_main();
    test_patch_pagezero();
    test_add_lc_id_dylib();
    test_transform_executable_to_dylib();

    printf("All tests completed\n");
    return EXIT_SUCCESS;
}
