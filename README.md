change MH-type, architecture and platform details of arm64/arm64e mach-o files

supports macos, ios, linux

```
Usage: machoe <input_path> [options]

Options:
  -o, --output <path>    Write output to path (default: modify in-place)
  -h, --help             Show help
  -r, --recursive        Process directories recursively
  -v, --verbose          Show detailed output

  --set-cpu <type>       Set ARM64 CPU subtype (arm64, arm64e)
  --set-platform <name>  Set platform (ios, macos, ios-simulator, etc)
  --minos <version>      Set min OS version (required with --set-platform)
  --sdk <version>        Set SDK version (required with --set-platform)
  --to-dylib             Convert MH_EXECUTE to MH_DYLIB (for dlopen() support)

Example: machoe foo.app/foo --set-cpu arm64 --set-platform ios-simulator --minos 14.0 --sdk 15.0
```

