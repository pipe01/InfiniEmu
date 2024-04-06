#define _POSIX_C_SOURCE 2

#include <unistd.h>
#include <stdio.h>

#include "nrf52832.h"
#include "gdb.h"

int main(int argc, char **argv)
{
    char *program_path = NULL;
    int c;

    while ((c = getopt(argc, argv, "f:")) != -1)
    {
        switch (c)
        {
        case 'f':
            program_path = optarg;
            break;
        default:
            return -1;
        }
    }

    if (program_path == NULL)
    {
        fprintf(stderr, "Usage: %s -f <program_path>\n", argv[0]);
        return -1;
    }

    FILE *f = fopen(program_path, "rb");
    if (f == NULL)
    {
        fprintf(stderr, "Failed to open %s\n", program_path);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *program = malloc(fsize);
    fread(program, fsize, 1, f);
    fclose(f);

    printf("Loaded %ld bytes from %s\n", fsize, program_path);

    NRF52832_t *nrf = nrf52832_new(program, fsize);

    free(program);

    gdb_t *gdb = gdb_new(nrf);
    gdb_start(gdb);

    for (;;)
    {
        nrf52832_step(nrf);
    }

    return 0;
}
