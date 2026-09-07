#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;    // MZ
    uint8_t  pad[58];
    uint32_t e_lfanew;   // PE Header Offset
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

#pragma pack(pop)

// Machine Type Function
const char* get_machine_type(uint16_t machine) {
    switch (machine) {
        case 0x8664: return "x64 (AMD64)";
        case 0x014C: return "x86 (Intel 386)";
        case 0xAA64: return "ARM64";
        default:     return "Unknown Architecture";
    }
}

// Characteristics Masking and Parsing Function
void parse_characteristics(uint16_t chars) {
    printf("Characteristics         : 0x%04X [ ", chars);
    if (chars & 0x0002) printf("EXE ");
    if (chars & 0x2000) printf("DLL ");
    if (chars & 0x0020) printf("LARGE_ADDRESS_AWARE ");
    if (chars & 0x0001) printf("RELOCS_STRIPPED ");
    if (chars & 0x1000) printf("SYSTEM_DRIVER ");
    printf("]\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <target_exe>\n", argv[0]);
        return 1;
    }

    FILE* file = fopen(argv[1], "rb");
    if (!file) {
        perror("File does not exist or cannot be opened");
        return 1;
    }

    // 1. DOS Header
    DOS_HEADER dos_hdr;
    fread(&dos_hdr, sizeof(DOS_HEADER), 1, file);

    if (dos_hdr.e_magic != 0x5A4D) {
        printf("Error: Not a valid PE file!\n");
        fclose(file);
        return 1;
    }

    // 2. PE Signature & File Header
    fseek(file, dos_hdr.e_lfanew, SEEK_SET);
    uint32_t pe_sig;
    fread(&pe_sig, sizeof(uint32_t), 1, file);

    FILE_HEADER file_hdr;
    fread(&file_hdr, sizeof(FILE_HEADER), 1, file);

    // TimeDateStamp Parsing
    time_t raw_time = (time_t)file_hdr.TimeDateStamp;
    char time_str[100];
    struct tm* timeinfo = gmtime(&raw_time);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S UTC", timeinfo);

    printf("======================================================================\n");
    printf("PE-INFO PARSER: %s\n", argv[1]);
    printf("======================================================================\n");
    printf("Machine                 : 0x%04X -> %s\n", file_hdr.Machine, get_machine_type(file_hdr.Machine));
    printf("Number of Sections      : %d\n", file_hdr.NumberOfSections);
    printf("Compilation Date (Stamp): %s\n", time_str);
    printf("Optional Header Size    : %d Byte\n", file_hdr.SizeOfOptionalHeader);
    parse_characteristics(file_hdr.Characteristics);
    printf("======================================================================\n\n");

    // 3. Section Headers
    long section_offset = dos_hdr.e_lfanew + sizeof(uint32_t) + sizeof(FILE_HEADER) + file_hdr.SizeOfOptionalHeader;
    fseek(file, section_offset, SEEK_SET);

    printf("%-10s %-12s %-12s %-12s %-12s\n", "SECTION NAME", "VIRT_SIZE", "VIRT_ADDR(RVA)", "RAW_OFFSET", "PERMISSIONS");
    printf("----------------------------------------------------------------------\n");

    for (int i = 0; i < file_hdr.NumberOfSections; i++) {
        SECTION_HEADER sec_hdr;
        fread(&sec_hdr, sizeof(SECTION_HEADER), 1, file);

        char sec_name[9] = {0};
        for(int j = 0; j < 8; j++) sec_name[j] = sec_hdr.Name[j];

        printf("%-10s 0x%08X   0x%08X     0x%08X   0x%08X\n", 
               sec_name, 
               sec_hdr.VirtualSize, 
               sec_hdr.VirtualAddress, 
               sec_hdr.PointerToRawData, 
               sec_hdr.Characteristics);
    }

    fclose(file);
    return 0;
}