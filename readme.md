# pe-info-parser

A small, dependency-free C tool for the first pass of static PE (Windows executable) triage. [pe-info-parser.c](pe-info-parser.c) is a single file that parses the PE structures by hand — no `windows.h`, no third-party libraries — so it builds with any C99 compiler on Windows or Linux.

It dumps the File Header, Section Table, Optional Header (mitigations, entry point), Data Directories, the Export Table (EAT) and the Import Table, and flags common packer / injector indicators along the way.

## Build

```sh
gcc -O2 -o pe-info-parser.exe pe-info-parser.c
```

Tested with MinGW-W64 GCC on Windows. MSVC (`cl /O2 pe-info-parser.c`) and Linux GCC/Clang should work as well; the only platform-specific bit is `_stricmp`/`strcasecmp`, which is handled by an `#ifdef`.

## Usage

```
pe-info-parser.exe <target_exe>
```

Walks `DOS_HEADER → PE signature → FILE_HEADER → OPTIONAL_HEADER64 → SECTION_HEADER[]`, then follows the Export and Import Directories through the section table with a manual RVA→file-offset translation. All offsets are bounds-checked against the file size, so a truncated or hand-crafted header produces an error instead of a crash or an infinite loop.

The report has six blocks.

**1. File header**

```
> pe-info-parser.exe sample.exe
======================================================================
PE-INFO PARSER: sample.exe
======================================================================
Machine                 : 0x8664 -> x64 (AMD64)
Number of Sections      : 18
Compilation Date (Stamp): 2026-09-10 19:40:58 UTC
Optional Header Size    : 240 Byte
Characteristics         : 0x0026 [ EXE LARGE_ADDRESS_AWARE ]
```

- **Machine** is decoded for x86 / x64 / ARM64.
- **Compilation Date** is the `TimeDateStamp` rendered in UTC. Remember this field is trivially forgeable.
- **Characteristics** decodes `EXE`, `DLL`, `LARGE_ADDRESS_AWARE`, `RELOCS_STRIPPED`, `SYSTEM_DRIVER`.

**2. Section table**

```
SECTION NAME VIRT_SIZE    VIRT_ADDR(RVA) RAW_OFFSET   PERMISSIONS
----------------------------------------------------------------------
.text      0x00003450   0x00001000     0x00000600   0x60000020
.data      0x000000C0   0x00005000     0x00003C00   0xC0000040
.rdata     0x00001408   0x00006000     0x00003E00   0x40000040
.idata     0x00000AD0   0x0000C000     0x00005E00   0x40000040
.tls       0x00000010   0x0000D000     0x00006A00   0xC0000040
...
```

**PERMISSIONS** is the raw section `Characteristics` DWORD (`0x20000000` execute, `0x40000000` read, `0x80000000` write). A writable+executable section is worth a second look.

**3. Optional header & mitigations**

```
======================================================================
OPTIONAL HEADER ANALYSIS & MITIGATIONS
======================================================================
ImageBase               : 0x0000000140000000
AddressOfEntryPoint     : 0x0000105F (RVA)
SizeOfImage             : 0x00018000 Byte
FileAlignment           : 0x00000200 | SectionAlignment: 0x00001000
Subsystem               : 3 [ Windows Console ]
Entry Point Section     : .text
DllCharacteristics      : 0x0160
  |-- ASLR (DYNAMIC_BASE) : ENABLED
  |-- DEP (NX_COMPAT)     : ENABLED
  |-- HIGH_ENTROPY_VA     : ENABLED
  |-- Guard CF            : DISABLED
  |-- Terminal Server     : NO
```

- **Entry Point Section** resolves `AddressOfEntryPoint` to the section that contains it. Anything other than `.text` is flagged as `[!] CRITICAL` — packers and injected stubs usually start execution from their own section. An entry point outside every section is reported as `UNKNOWN`.
- **FileAlignment == SectionAlignment** is flagged as a warning. Normal linkers use `0x200` / `0x1000`; equal values are typical of packed images and manually built shellcode loaders.
- **DllCharacteristics** is broken out into ASLR, DEP, high-entropy VA, CFG and Terminal Server awareness. A disabled ASLR or DEP gets a `[!]` marker.

**4. Data directories**

```
======================================================================
DATA DIRECTORIES (CRITICAL INDEXES)
======================================================================
[00] EXPORT Directory        : RVA 0x00000000 | Size 0x00000000 [ NOT PRESENT ]
[01] IMPORT Directory        : RVA 0x0000C000 | Size 0x00000AD0 [ PRESENT ]
[02] RESOURCE Directory      : RVA 0x0000E000 | Size 0x000001E0 [ PRESENT ]
[04] SECURITY Directory      : RVA 0x00000000 | Size 0x00000000 [ NOT PRESENT ]
[05] BASERELOC Directory     : RVA 0x0000F000 | Size 0x0000008C [ PRESENT ]
[09] TLS Directory           : RVA 0x00006DC0 | Size 0x00000028 [ PRESENT ] -> [!] CRITICAL: TLS Callback Present (Anti-Debug/Early Exec)!
[10] LOAD_CONFIG Directory   : RVA 0x00000000 | Size 0x00000000 [ NOT PRESENT ]
[13] DELAY_IMPORT Directory  : RVA 0x00000000 | Size 0x00000000 [ NOT PRESENT ]
```

Only the triage-relevant indexes are listed (export, import, resource, security, base relocation, TLS, load config, delay import). Three of them carry extra heuristics:

- **SECURITY present** → an Authenticode signature is attached. Presence is reported, the signature is not validated.
- **TLS present** → TLS callbacks run before the entry point, a classic anti-debug / early-execution spot. Note that MinGW-built binaries (like the sample above) legitimately carry a TLS directory, so treat this as "look here", not "malicious".
- **RESOURCE larger than 64 KiB** → possible embedded payload (droppers commonly stash the second stage in `.rsrc`).

**5. Exports**

```
======================================================================
EXPORT DIRECTORY ANALYSIS (EAT)
======================================================================
Module Name             : VERSION.dll
Base Ordinal            : 1
Total Functions         : 17
Named Functions         : 17
----------------------------------------------------------------------
[+] Printing first 15 exported functions:

ORDINAL FUNC RVA   FOFFSET      FUNCTION NAME
----------------------------------------------------------------------
@1      0x000010F0 0x000010F0   GetFileVersionInfoA
@2      0x00001110 0x00001110   GetFileVersionInfoByHandle
@3      0x00001AB0 0x00001AB0   GetFileVersionInfoExA
...
@15     0x00005F87 0x00005F87   VerLanguageNameW
... (2 more exports truncated)
```

Reads `IMAGE_EXPORT_DIRECTORY` (index 0 of the data directories) and walks the three parallel tables — `AddressOfNames`, `AddressOfNameOrdinals`, `AddressOfFunctions` — to resolve each named export to its real ordinal and code RVA. This is the block that matters for DLL samples: DLL side-loading payloads, hijacked system DLLs and reflective loaders tend to have a tell-tale export list (a single `DllMain`-style stub, `ReflectiveLoader`, or a cloned export set of the DLL they impersonate).

- **Module Name** is the internal name stored in the export table. If it does not match the file name on disk, the DLL has been renamed — normal for side-loading kits.
- **ORDINAL** is `Base + NameOrdinal[i]`, i.e. the number the DLL actually exports it under (`GetProcAddress` by ordinal works with this value).
- **FOFFSET** is the function's raw file offset after RVA translation. An RVA that cannot be mapped to any section prints as `0xFFFFFFFF`.
- Output is capped at the first 15 named exports; the remaining count is reported so you know when to open the file in a proper disassembler. A file without an export directory (most `.exe`s) prints a single `[-] No Export Directory Found` line.

**6. Imports**

```
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

For `KERNEL32.dll` the import list is filtered to cut noise:

- `[!] CRITICAL API` — process/memory-manipulation APIs commonly seen in loaders, injectors and droppers (`VirtualAlloc[Ex]`, `WriteProcessMemory`, `CreateRemoteThread`, `OpenProcess`, `CreateProcess*`, `WinExec`, `LoadLibrary[A|W]`, …).
- `[~] CRT Baseline` — APIs almost every MSVC/MinGW CRT pulls in (`GetProcAddress`, `VirtualProtect`, `LoadLibraryExW`, `InitializeSListHead`, `SetUnhandledExceptionFilter`). Shown so you can tell "the CRT did it" from "the author did it".
- Everything else from `KERNEL32` is collapsed into a `(... N hidden KERNEL32 APIs)` count.

Imports from every other DLL are listed in full. Ordinal-only imports are printed as `Ordinal: N`.

## Limitations

- Only **PE32+ (64-bit)** images are supported. 32-bit PE32 files are rejected with an error rather than mis-parsed.
- The import walker handles the classic Import Directory only. Delay-load imports and the load config are reported as present/absent in the data directory block but not parsed.
- The export walker lists **named** exports only (the first 15). Ordinal-only exports (`Total Functions > Named Functions`) are counted but not listed, and forwarded exports (`KERNEL32.HeapAlloc`-style strings in place of code) are printed with their RVA as if they were code.
- Section names are truncated at 8 bytes as stored in the header; long names via the string table (`/4`, `/14`, … in GCC-built binaries) are not resolved.
- The `[!]` markers are heuristics for prioritising what to look at next, not verdicts. Legitimate software trips several of them (see the TLS note above).

Compiled `.exe` files are ignored via `.gitignore`; rebuild from source with the command above.
