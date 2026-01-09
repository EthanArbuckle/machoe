//
//  main.c
//  machoe
//
//  Created by Ethan Arbuckle
//

#include "machoe.h"
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <errno.h>


void print_usage(const char *prog_name) {
    printf("Usage: %s <input_path> [options]\n\n", basename((char *)prog_name));
    printf("Options:\n");
    printf("  -o, --output <path>    Write output to path (default: modify in-place)\n");
    printf("  -h, --help             Show help\n");
    printf("  -r, --recursive        Process directories recursively\n");
    printf("  -v, --verbose          Show detailed output\n\n");
    printf("Modification Options:\n");
    printf("  --set-cpu <type>       Set ARM64 CPU subtype (arm64, arm64e)\n");
    printf("  --set-platform <name>  Set platform (ios, macos, ios-simulator, etc)\n");
    printf("  --minos <version>      Set min OS version (required with --set-platform)\n");
    printf("  --sdk <version>        Set SDK version (required with --set-platform)\n");
    printf("  --normalize-frameworks Update /System/Library/Frameworks paths for target platform\n");
    printf("  --to-dylib             Convert MH_EXECUTE to MH_DYLIB (for dlopen() support)\n\n");
    printf("Example: %s foo.bin --set-platform macos --minos 11.0 --sdk 12.0 --normalize-frameworks\n", basename((char *)prog_name));
}

int main(int argc, char *argv[]) {
    tool_config_t config = {0};
    config.recursive = false;
    config.modify_cpu = false;
    config.modify_platform = false;
    config.verbose = false;
    config.normalize_frameworks = false;
    config.convert_to_dylib = false;

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
        {"normalize-frameworks", no_argument, 0, 0x1001},
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
            case 0x1001:
                config.normalize_frameworks = true;
                break;
            default: {
                if (opt == '?') {
                    printf("Invalid option or missing argument\n");
                }
                else {
                    printf("Unknown option character `\\x%x'\n", optopt);
                }

                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
        }
    }

    if (optind >= argc) {
        printf("Input path is required\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    config.input_path = argv[optind];

    if (!config.modify_cpu && !config.modify_platform && !config.normalize_frameworks && !config.convert_to_dylib) {
        printf("No action specified. Use --set-cpu, --set-platform, --normalize-frameworks, or --to-dylib\n");
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

    process_binaries_in_directory(config.input_path, &config);

    return EXIT_SUCCESS;
}
