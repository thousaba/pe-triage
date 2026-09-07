#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#ifdef _WIN32
#define STRICMP _stricmp
#else
#include <strings.h>
#define STRICMP strcasecmp
#endif

#define INVALID_OFFSET 0xFFFFFFFF

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;
    uint8_t  pad[58];
    uint32_t e_lfanew;
} DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} FILE_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} OPTIONAL_HEADER64;

typedef struct {
    uint8_t  Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;     
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} SECTION_HEADER;

typedef struct {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;               
    uint32_t FirstThunk;          
} IMAGE_IMPORT_DESCRIPTOR;

#pragma pack(pop)

const char* get_machine_type(uint16_t machine) {
    switch (machine) {
        case 0x8664: return "x64 (AMD64)";
        case 0x014C: return "x86 (Intel 386)";
        case 0xAA64: return "ARM64";
        default:     return "Unknown Architecture";
    }
}

void parse_characteristics(uint16_t chars) {
    printf("Characteristics         : 0x%04X [ ", chars);
    if (chars & 0x0002) printf("EXE ");
    if (chars & 0x2000) printf("DLL ");
    if (chars & 0x0020) printf("LARGE_ADDRESS_AWARE ");
    if (chars & 0x0001) printf("RELOCS_STRIPPED ");
    if (chars & 0x1000) printf("SYSTEM_DRIVER ");
    printf("]\n");
}

uint32_t rva_to_offset(uint32_t rva, SECTION_HEADER* sections, uint16_t num_sections) {
    if (rva == 0) return INVALID_OFFSET;
    for (int i = 0; i < num_sections; i++) {
        if (rva >= sections[i].VirtualAddress && 
            rva < (sections[i].VirtualAddress + sections[i].VirtualSize)) {
            return (rva - sections[i].VirtualAddress) + sections[i].PointerToRawData;
        }
    }
    return INVALID_OFFSET;
}

int is_crt_baseline_api(const char* api_name) {
    const char* baseline_apis[] = {
        "GetProcAddress", "VirtualProtect", "LoadLibraryExW", 
        "InitializeSListHead", "SetUnhandledExceptionFilter", NULL
    };
    for (int i = 0; baseline_apis[i] != NULL; i++) {
        if (strcmp(api_name, baseline_apis[i]) == 0) return 1;
    }
    return 0;
}

int is_critical_kernel32_api(const char* api_name) {
    const char* critical_apis[] = {
        "LoadLibraryA", "LoadLibraryW", "VirtualAlloc", "VirtualAllocEx", 
        "VirtualProtectEx", "VirtualQueryEx", "ReadProcessMemory", 
        "WriteProcessMemory", "CreateRemoteThread", "OpenProcess", 
        "WinExec", "CreateProcessA", "CreateProcessW", NULL
    };
    for (int i = 0; critical_apis[i] != NULL; i++) {
        if (strcmp(api_name, critical_apis[i]) == 0) return 1;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <target_exe>\n", argv[0]);
        return 1;
    }

    FILE* file = fopen(argv[1], "rb");
    if (!file) {
        perror("Error: Could not open file");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long fs = ftell(file);
    if (fs < 0) {
        perror("[-] Error: File size could not be determined (ftell)");
        fclose(file);
        return 1;
    }
    uint32_t file_size = (uint32_t)fs;
    rewind(file);

    DOS_HEADER dos_hdr;
    if (fread(&dos_hdr, sizeof(DOS_HEADER), 1, file) != 1 || dos_hdr.e_magic != 0x5A4D) {
        printf("[-] Error: Not a valid PE file (no MZ signature) or file is corrupted!\n");
        fclose(file);
        return 1;
    }

    if (dos_hdr.e_lfanew >= file_size) {
        printf("[-] Error: PE header offset exceeds file size!\n");
        fclose(file);
        return 1;
    }

    fseek(file, dos_hdr.e_lfanew, SEEK_SET);
    uint32_t pe_sig;
    if (fread(&pe_sig, sizeof(uint32_t), 1, file) != 1 || pe_sig != 0x00004550) {
        printf("[-] Error: PE signature (PE\\0\\0) not found!\n");
        fclose(file);
        return 1;
    }

    FILE_HEADER file_hdr;
    if (fread(&file_hdr, sizeof(FILE_HEADER), 1, file) != 1) {
        fclose(file);
        return 1;
    }

    OPTIONAL_HEADER64 opt_hdr;
    if (fread(&opt_hdr, sizeof(OPTIONAL_HEADER64), 1, file) != 1) {
        fclose(file);
        return 1;
    }

    if (opt_hdr.Magic != 0x020B) {
        printf("[-] Error: This tool currently only supports PE32+ (64-bit) binaries. (Incoming Magic: 0x%04X)\n", opt_hdr.Magic);
        fclose(file);
        return 1;
    }

    time_t raw_time = (time_t)file_hdr.TimeDateStamp;
    char time_str[100];
    struct tm* timeinfo = gmtime(&raw_time);
    if (timeinfo) {
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S UTC", timeinfo);
    } else {
        strcpy(time_str, "Unknown Date");
    }

    printf("======================================================================\n");
    printf("PE-INFO PARSER: %s\n", argv[1]);
    printf("======================================================================\n");
    printf("Machine                 : 0x%04X -> %s\n", file_hdr.Machine, get_machine_type(file_hdr.Machine));
    printf("Number of Sections      : %d\n", file_hdr.NumberOfSections);
    printf("Compilation Date (Stamp): %s\n", time_str);
    printf("Optional Header Size    : %d Byte\n", file_hdr.SizeOfOptionalHeader);
    parse_characteristics(file_hdr.Characteristics);
    printf("======================================================================\n\n");

    long section_offset = dos_hdr.e_lfanew + 4 + sizeof(FILE_HEADER) + file_hdr.SizeOfOptionalHeader;
    if (section_offset < 0 || (uint32_t)section_offset >= file_size) {
        printf("[-] Error: Section table offset is invalid!\n");
        fclose(file);
        return 1;
    }
    fseek(file, section_offset, SEEK_SET);

    SECTION_HEADER* sections = malloc(sizeof(SECTION_HEADER) * file_hdr.NumberOfSections);
    if (!sections || fread(sections, sizeof(SECTION_HEADER), file_hdr.NumberOfSections, file) != file_hdr.NumberOfSections) {
        printf("[-] Error: Could not read section table!\n");
        if(sections) free(sections);
        fclose(file);
        return 1;
    }

    printf("%-10s %-12s %-12s %-12s %-12s\n", "SECTION NAME", "VIRT_SIZE", "VIRT_ADDR(RVA)", "RAW_OFFSET", "PERMISSIONS");
    printf("----------------------------------------------------------------------\n");

    for (int i = 0; i < file_hdr.NumberOfSections; i++) {
        char sec_name[9] = {0};
        memcpy(sec_name, sections[i].Name, 8);

        printf("%-10s 0x%08X   0x%08X     0x%08X   0x%08X\n", 
               sec_name, sections[i].VirtualSize, sections[i].VirtualAddress, 
               sections[i].PointerToRawData, sections[i].Characteristics);
    }

    // DataDirectory sinir kontrolu
    uint32_t import_rva = 0;
    if (opt_hdr.NumberOfRvaAndSizes >= 2) {
        import_rva = opt_hdr.DataDirectory[1].VirtualAddress;
    }

    printf("\n======================================================================\n");
    printf("IMPORTS (STATIC DLLs and CRITICAL APIs)\n");
    printf("======================================================================\n");

    if (import_rva == 0) {
        printf("[-] Static Import Table Not Found or RVA is 0!\n");
    } else {
        uint32_t import_offset = rva_to_offset(import_rva, sections, file_hdr.NumberOfSections);
        
        if (import_offset == INVALID_OFFSET || import_offset >= file_size) {
            printf("[-] Error: Import table points to an invalid offset!\n");
        } else {
            fseek(file, import_offset, SEEK_SET);

            IMAGE_IMPORT_DESCRIPTOR import_desc;
            while (1) {
                if (fread(&import_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, file) != 1) break;
                if (import_desc.Name == 0) break;

                long current_pos = ftell(file);
                uint32_t name_offset = rva_to_offset(import_desc.Name, sections, file_hdr.NumberOfSections);
                
                if (name_offset != INVALID_OFFSET && name_offset < file_size) {
                    fseek(file, name_offset, SEEK_SET);
                    
                    char dll_name[128] = {0};
                    int ch; 
                    int idx = 0;
                    while ((ch = fgetc(file)) != 0 && ch != EOF && idx < 127) {
                        dll_name[idx++] = (char)ch;
                    }

                    int is_kernel32 = (STRICMP(dll_name, "KERNEL32.dll") == 0);
                    printf("\n[+] Imported DLL: %s\n", dll_name);

                    uint32_t thunk_rva = import_desc.OriginalFirstThunk ? import_desc.OriginalFirstThunk : import_desc.FirstThunk;
                    uint32_t thunk_offset = rva_to_offset(thunk_rva, sections, file_hdr.NumberOfSections);
                    
                    if (thunk_offset != INVALID_OFFSET && thunk_offset < file_size) {
                        fseek(file, thunk_offset, SEEK_SET);
                        uint64_t thunk_data;
                        int hidden_k32_count = 0;

                        while (1) {
                            if (fread(&thunk_data, sizeof(uint64_t), 1, file) != 1) break;
                            if (thunk_data == 0) break;

                            if (thunk_data & (1ULL << 63)) {
                                printf("    |-- Ordinal: %" PRIu64 "\n", thunk_data & 0xFFFF);
                            } else {
                                long inner_pos = ftell(file);
                                uint32_t thunk_val_offset = rva_to_offset((uint32_t)thunk_data, sections, file_hdr.NumberOfSections);
                                
                                if (thunk_val_offset != INVALID_OFFSET && thunk_val_offset < file_size - 2) {
                                    uint32_t func_name_offset = thunk_val_offset + 2;
                                    fseek(file, func_name_offset, SEEK_SET);

                                    char func_name[128] = {0};
                                    int f_idx = 0;
                                    while ((ch = fgetc(file)) != 0 && ch != EOF && f_idx < 127) {
                                        func_name[f_idx++] = (char)ch;
                                    }

                                    if (is_kernel32) {
                                        if (is_critical_kernel32_api(func_name)) {
                                            printf("    |-- [!] CRITICAL API: %s\n", func_name);
                                        } else if (is_crt_baseline_api(func_name)) {
                                            printf("    |-- [~] CRT Baseline: %s\n", func_name);
                                        } else {
                                            hidden_k32_count++;
                                        }
                                    } else {
                                        printf("    |-- API: %s\n", func_name);
                                    }
                                }
                                if(inner_pos >= 0) fseek(file, inner_pos, SEEK_SET);
                            }
                        }

                        if (is_kernel32 && hidden_k32_count > 0) {
                            printf("    |-- (... %d hidden KERNEL32 APIs)\n", hidden_k32_count);
                        }
                    }
                }
                if(current_pos >= 0) fseek(file, current_pos, SEEK_SET);
            }
        }
    }

    free(sections);
    fclose(file);
    return 0;
}