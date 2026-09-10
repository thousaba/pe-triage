<<<<<<< HEAD
# pe-triage
=======
<<<<<<< HEAD
# Based Binary Analysis & PE Internals Utilities
=======
# pe-triage
>>>>>>> 517dc8c (fix: harden PE info-parser against malformed files, fix integer overflows and infinite loops)
>>>>>>> d379102 (feat(parser): harden RVA resolution logic and add PE Data Directories triage)

Small, dependency-free C tools for the first pass of static PE (Windows executable) triage. Each tool is a single `.c` file that parses the PE structures by hand — no `windows.h`, no third-party libraries — so they build with any C99 compiler on Windows or Linux.

| Tool | What it does |
|---|---|
| [pe-pattern-finder.c](pe-pattern-finder.c) | Sanity check: does the file start with `MZ`, and where is the `PE\0\0` signature? |
| [pe-info-parser.c](pe-info-parser.c) | Dumps File Header, Section Table and the Import Table; flags suspicious `KERNEL32` APIs |
| [pe-section-strings-extractor.c](pe-section-strings-extractor.c) | `strings`-style ASCII + UTF-16LE extraction, with every hit mapped to the PE section it lives in |

## Build

```sh
gcc -O2 -o pe-pattern-finder.exe            pe-pattern-finder.c
gcc -O2 -o pe-info-parser.exe               pe-info-parser.c
gcc -O2 -o pe-section-strings-extractor.exe pe-section-strings-extractor.c
```

Tested with MinGW-W64 GCC on Windows. MSVC (`cl /O2 file.c`) and Linux GCC/Clang should work as well; the only platform-specific bit is `_stricmp`/`strcasecmp`, which is handled by an `#ifdef`.

## Usage

### pe-pattern-finder

Reads the whole file into memory, checks for the DOS `MZ` magic and scans the buffer for the `PE\0\0` signature. Useful for checking a blob that *might* be a PE (dumped memory, carved file, wrong extension).

```
> pe-pattern-finder.exe sample.exe
File Name: sample.exe
 File size: 70098 bytes
PE Header (MZ) found at the beginning of the file.
PE Signature (PE\0\0) found at offset: 128 (0x80)
```

### pe-info-parser

Walks `DOS_HEADER → PE signature → FILE_HEADER → OPTIONAL_HEADER64 → SECTION_HEADER[]`, then follows the Import Directory (`DataDirectory[1]`) through the section table with a manual RVA→file-offset translation.

```
> pe-info-parser.exe sample.exe
======================================================================
PE-INFO PARSER: sample.exe
======================================================================
Machine                 : 0x8664 -> x64 (AMD64)
Number of Sections      : 18
Compilation Date (Stamp): 2026-09-07 18:26:21 UTC
Optional Header Size    : 240 Byte
Characteristics         : 0x0026 [ EXE LARGE_ADDRESS_AWARE ]
======================================================================

SECTION NAME VIRT_SIZE    VIRT_ADDR(RVA) RAW_OFFSET   PERMISSIONS
----------------------------------------------------------------------
.text      0x00003500   0x00001000     0x00000600   0x60000020
.data      0x000000C0   0x00005000     0x00003C00   0xC0000040
.rdata     0x00000DE8   0x00006000     0x00003E00   0x40000040
...

======================================================================
IMPORTS (STATIC DLLs and CRITICAL APIs)
======================================================================

[+] Imported DLL: KERNEL32.dll
    |-- [~] CRT Baseline: GetProcAddress
    |-- [!] CRITICAL API: LoadLibraryA
    |-- [~] CRT Baseline: SetUnhandledExceptionFilter
    |-- [~] CRT Baseline: VirtualProtect
    |-- (... 10 hidden KERNEL32 APIs)

[+] Imported DLL: api-ms-win-crt-heap-l1-1-0.dll
    |-- API: calloc
    |-- API: free
    |-- API: malloc
```

Output notes:

- **Machine** is decoded for x86 / x64 / ARM64.
- **Compilation Date** is the `TimeDateStamp` rendered in UTC. Remember this field is trivially forgeable.
- **Characteristics** decodes `EXE`, `DLL`, `LARGE_ADDRESS_AWARE`, `RELOCS_STRIPPED`, `SYSTEM_DRIVER`.
- **PERMISSIONS** is the raw section `Characteristics` DWORD (`0x20000000` execute, `0x40000000` read, `0x80000000` write). A writable+executable section is worth a second look.
- For `KERNEL32.dll` the import list is filtered to cut noise:
  - `[!] CRITICAL API` — process/memory-manipulation APIs commonly seen in loaders, injectors and droppers (`VirtualAlloc[Ex]`, `WriteProcessMemory`, `CreateRemoteThread`, `OpenProcess`, `CreateProcess*`, `WinExec`, `LoadLibrary[A|W]`, …).
  - `[~] CRT Baseline` — APIs almost every MSVC/MinGW CRT pulls in (`GetProcAddress`, `VirtualProtect`, `LoadLibraryExW`, `InitializeSListHead`, `SetUnhandledExceptionFilter`). Shown so you can tell "the CRT did it" from "the author did it".
  - Everything else from `KERNEL32` is collapsed into a `(... N hidden KERNEL32 APIs)` count.
- Imports from every other DLL are listed in full. Ordinal-only imports are printed as `Ordinal: N`.

### pe-section-strings-extractor

```
pe-section-strings-extractor.exe <file> [min_length]
```

`min_length` defaults to 4. Every hit is printed as `offset [section] [encoding] : text`.

```
> pe-section-strings-extractor.exe sample.exe 8
======================================================================
MY_STRINGS PARSER v2.0 | Hedef: sample.exe (70098 Bayt) | Min Len: 8
======================================================================

[+] --- BULUNAN ASCII STRING'LER --- [+]
0x0000004D [HEADER/HEADER_GAP] [ASCII] : !This program cannot be run in DOS mode.
0x00003E00 [.rdata    ] [ASCII] : libgcc_s_dw2-1.dll
0x00003E13 [.rdata    ] [ASCII] : __register_frame_info
0x00003F4A [.rdata    ] [ASCII] : LoadLibraryA
0x00003F64 [.rdata    ] [ASCII] : VirtualAlloc
...

[+] --- BULUNAN UTF-16LE (WIDE) STRING'LER --- [+]
...
```

The section column is what makes this more useful than plain `strings`: a URL or API name in `.rdata` is ordinary, the same thing sitting in `.text` or in an oddly named section is a signal. `HEADER/HEADER_GAP` means the offset is outside every section's raw data range (PE headers, padding, or an overlay appended after the last section).

If the file is not a PE (no `MZ` / `PE\0\0`), section mapping is skipped and every string is reported as `UNKNOWN` — the tool still works as a generic string extractor.

## Limitations

- `pe-info-parser` only supports **PE32+ (64-bit)** images. 32-bit PE32 files are rejected with an error rather than mis-parsed.
- The import walker handles the classic Import Directory only — no delay-load imports, no bound imports, no export table.
- Section names are truncated at 8 bytes as stored in the header; long names via the string table (`/4`, `/14`, … in GCC-built binaries) are not resolved.
- All three tools load the entire file into memory. Fine for executables, not meant for multi-GB blobs.
- String extraction uses `isprint()` on single bytes; the UTF-16 scanner only catches the Latin/ASCII range of wide strings.

## Layout

```
pe-pattern-finder.c              # MZ / PE\0\0 signature scan
pe-info-parser.c                 # headers, sections, imports
pe-section-strings-extractor.c   # ASCII + UTF-16LE strings w/ section mapping
```

The `.exe` files in the working tree are local build outputs; rebuild from source with the commands above.
