#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define macro_string2(x) #x
#define macro_string(x) macro_string2(x)

static inline uint8_t *read_file_u8(const char *path, size_t *size)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
    {
        fprintf(stderr, "Failed to open %s\n", path);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(fsize);
    if (fread(data, 1, fsize, f) != (size_t)fsize)
    {
        fprintf(stderr, "Failed to read %s\n", path);
        return NULL;
    }
    fclose(f);

    *size = fsize;
    return data;
}
