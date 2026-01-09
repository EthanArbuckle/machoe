#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>


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
    bool normalize_frameworks;
} tool_config_t;


bool parse_version(const char *version_str, uint32_t *version_out);

bool platform_name_to_id(const char *name, uint32_t *id_out);
const char *platform_id_to_name(uint32_t id);

bool subtype_name_to_id(const char *name, cpu_subtype_t *id_out);
const char *subtype_id_to_name(cpu_subtype_t id);

bool process_fat_file(FILE *file, const char *filepath, bool needs_swap, struct stat *st, const tool_config_t *config);
bool process_binary(const char *filepath, const tool_config_t *config);
void process_binaries_in_directory(const char *path, const tool_config_t *config);
