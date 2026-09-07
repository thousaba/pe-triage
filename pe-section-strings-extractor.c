#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>

#define DEFAULT_MIN_LEN 4

// PE Section Header Structure
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
} MY_IMAGE_SECTION_HEADER;

typedef struct {
    MY_IMAGE_SECTION_HEADER *headers;
    uint16_t count;
} PE_SECTIONS;

// Section Name Retrieval Function
const char* get_section_name(size_t offset, const PE_SECTIONS *sections) {
    if (!sections || !sections->headers) return "UNKNOWN";

    for (uint16_t i = 0; i < sections->count; i++) {
        uint32_t start = sections->headers[i].PointerToRawData;
        uint32_t end = start + sections->headers[i].SizeOfRawData;

        if (offset >= start && offset < end) {
            static char sec_name[9];
            memcpy(sec_name, sections->headers[i].Name, 8);
            sec_name[8] = '\0';
            return sec_name;
        }
    }
    return "HEADER/HEADER_GAP";
}

// PE Section Header Parsing Function
void parse_pe_sections(const uint8_t *buf, size_t size, PE_SECTIONS *out_sec) {
    out_sec->headers = NULL;
    out_sec->count = 0;

    if (size < 0x40) return; 
    if (buf[0] != 'M' || buf[1] != 'Z') return; 

    uint32_t e_lfanew = *(uint32_t*)(buf + 0x3C);
    if (e_lfanew + 24 > size) return;
    if (memcmp(buf + e_lfanew, "PE\0\0", 4) != 0) return; 

    uint16_t num_sections = *(uint16_t*)(buf + e_lfanew + 6);
    uint16_t opt_header_size = *(uint16_t*)(buf + e_lfanew + 20);

    size_t sec_table_offset = e_lfanew + 24 + opt_header_size;
    if (sec_table_offset + (num_sections * sizeof(MY_IMAGE_SECTION_HEADER)) > size) return;

    out_sec->headers = (MY_IMAGE_SECTION_HEADER*)(buf + sec_table_offset);
    out_sec->count = num_sections;
}

// ASCII SCAN ENGINE
void scan_ascii(const uint8_t *buf, size_t size, size_t min_len, const PE_SECTIONS *sec) {
    printf("\n[+] --- BULUNAN ASCII STRING'LER --- [+]\n");
    size_t len = 0;

    for (size_t i = 0; i < size; i++) {
        if (isprint(buf[i])) {
            len++;
        } else {
            if (len >= min_len) {
                size_t start = i - len;
                printf("0x%08zX [%-10s] [ASCII] : ", start, get_section_name(start, sec));
                for (size_t j = start; j < i; j++) putchar(buf[j]);
                printf("\n");
            }
            len = 0;
        }
    }
    if (len >= min_len) {
        size_t start = size - len;
        printf("0x%08zX [%-10s] [ASCII] : ", start, get_section_name(start, sec));
        for (size_t j = start; j < size; j++) putchar(buf[j]);
        printf("\n");
    }
}

// UTF-16 SCAN ENGINE
void scan_utf16le(const uint8_t *buf, size_t size, size_t min_len, const PE_SECTIONS *sec) {
    printf("\n[+] --- BULUNAN UTF-16LE (WIDE) STRING'LER --- [+]\n");
    
    for (size_t i = 0; i < size - 1; i++) {
        if (isprint(buf[i]) && buf[i + 1] == 0x00) {
            size_t start = i;
            size_t len = 0;

            while ((i + 1 < size) && isprint(buf[i]) && buf[i + 1] == 0x00) {
                len++;
                i += 2;
            }

            if (len >= min_len) {
                printf("0x%08zX [%-10s] [UTF-16]: ", start, get_section_name(start, sec));
                for (size_t j = start; j < start + (len * 2); j += 2) {
                    putchar(buf[j]);
                }
                printf("\n");
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Kullanim: %s <dosya_adi.exe> [min_uzunluk]\n", argv[0]);
        return 1;
    }

    size_t min_len = DEFAULT_MIN_LEN;
    if (argc >= 3) {
        int parsed_len = atoi(argv[2]);
        if (parsed_len > 0) min_len = (size_t)parsed_len;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("[-] Dosya acilamadi");
        return 1;
    }

    // 1. ftell long kontrolü ve cast
    if (fseek(f, 0, SEEK_END) != 0) {
        perror("[-] fseek hatasi");
        fclose(f);
        return 1;
    }

    long tmp_size = ftell(f);
    if (tmp_size < 0) {
        perror("[-] ftell hatasi (negatif boyut)");
        fclose(f);
        return 1;
    }
    size_t file_size = (size_t)tmp_size;

    if (fseek(f, 0, SEEK_SET) != 0) {
        perror("[-] fseek hatasi");
        fclose(f);
        return 1;
    }

    uint8_t *buf = (uint8_t *)malloc(file_size);
    if (!buf) {
        fprintf(stderr, "[-] Bellek ayrilamadi! (Boyut: %zu bayt)\n", file_size);
        fclose(f);
        return 1;
    }

    // 2. Strict fread checking
    size_t bytes_read = fread(buf, 1, file_size, f);
    fclose(f);

    if (bytes_read != file_size) {
        fprintf(stderr, "[-] Okuma Hatasi: %zu bayt istendi, %zu bayt okundu!\n", file_size, bytes_read);
        free(buf);
        return 1;
    }

    // 3. PE Section Mapping
    PE_SECTIONS pe_sec;
    parse_pe_sections(buf, file_size, &pe_sec);

    printf("======================================================================\n");
    printf("MY_STRINGS PARSER v2.0 | Hedef: %s (%zu Bayt) | Min Len: %zu\n", argv[1], file_size, min_len);
    printf("======================================================================\n");

    scan_ascii(buf, file_size, min_len, &pe_sec);
    scan_utf16le(buf, file_size, min_len, &pe_sec);

    free(buf);
    return 0;
}