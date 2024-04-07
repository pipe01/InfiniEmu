#define _POSIX_C_SOURCE 2

#include <unistd.h>
#include <stdio.h>

#include "nrf52832.h"
#include "gdb.h"

int main(int argc, char **argv)
{
    char *program_path = NULL;
    bool run_gdb = false;
    bool wait_gdb = false;

    int c;

    while ((c = getopt(argc, argv, "dwf:")) != -1)
    {
        switch (c)
        {
        case 'f':
            program_path = optarg;
            break;

        case 'd':
            run_gdb = true;
            break;

        case 'w':
            wait_gdb = true;
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
    cpu_t *cpu = nrf52832_get_cpu(nrf);

    free(program);

    gdb_t *gdb = NULL;

    if (run_gdb)
    {
        gdb = gdb_new(nrf, false);
        gdb_start(gdb);

        if (wait_gdb)
        {
            printf("Waiting for GDB connection...\n");
            gdb_wait_for_connection(gdb);
        }
    }

    for (;;)
    {
        if (gdb != NULL)
        {
            gdb_check_breakpoint(gdb, cpu_reg_read(cpu, ARM_REG_PC) - 4);
            gdb_wait_for_unpause(gdb);
        }

        nrf52832_step(nrf);
    }

    return 0;
}
