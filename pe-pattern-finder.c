# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <string.h>

long find_pattern(const uint8_t *buffer, size_t buffer_size, const uint8_t *pattern, size_t pattern_size) {
    if (pattern_size > buffer_size) {
        return -1; // Pattern is larger than the buffer
    }

    for (size_t i = 0; i <= buffer_size - pattern_size; i++) {
        if(memcmp(buffer + i, pattern, pattern_size) == 0) {
            return (long)i; // Pattern found at index i
        }
    }

    return -1; // Pattern not found
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file_path>\n", argv[0]);
        return 1;
    }

    const char *file_name = argv[1];

    FILE *file = fopen(file_name, "rb"); 
    if (!file) {
        perror("Failed to open file");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    printf("File Name: %s\n File size: %ld bytes\n", file_name, file_size);

    if (file_size < 2) {
        printf("File is too small to contain the PE signature.\n");
        fclose(file);
        return 1;
    }

    uint8_t *buffer = (uint8_t *)malloc(file_size);
    if (buffer==NULL) {
        perror("Failed to allocate memory");
        fclose(file);
        return 1;
    }

    size_t bytes_read = fread(buffer, 1, file_size, file);
    fclose(file);

    if (bytes_read != file_size) {
        perror("Failed to read the entire file");
        free(buffer);
        return 1;
    }

    if (buffer[0] == 0x4D && buffer[1] == 0x5A) {
        printf("PE Header (MZ) found at the beginning of the file.\n");
    } else {
        printf("PE Header (MZ) not found at the beginning of the file.\n");
    }

    uint8_t pe_pattern[] = { 0x50, 0x45, 0x00, 0x00 }; // PE
    long found_offset = find_pattern(buffer, file_size, pe_pattern, sizeof(pe_pattern));

    if (found_offset != -1) {
        printf("PE Signature (PE\\0\\0) found at offset: %ld (0x%lX)\n", found_offset, found_offset);
    } else {
        printf("PE Signature (PE\\0\\0) not found in the file.\n");
    }

    free(buffer);
    buffer = NULL; // Avoid dangling pointer

    return 0;
}