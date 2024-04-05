#define _POSIX_C_SOURCE 2

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>

#include <capstone/capstone.h>

#include "cpu.h"
#include "byte_util.h"

#define NRF52832_SRAM_SIZE 0x10000

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
        fprintf(stderr, "Usage: %s -p <program_path>\n", argv[0]);
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

    uint8_t *buffer = malloc(fsize);
    fread(buffer, fsize, 1, f);
    fclose(f);

    printf("Loaded %ld bytes from %s\n", fsize, program_path);

    memreg_t *mem_flash = memreg_new_simple(0, buffer, fsize);

    uint8_t *sram = malloc(NRF52832_SRAM_SIZE);
    memreg_t *mem_ram = memreg_new_simple(x(2000, 0000), sram, NRF52832_SRAM_SIZE);
    mem_flash->next = mem_ram;

    cpu_t *cpu = cpu_new(buffer, fsize, mem_flash);

    cpu_reset(cpu);

    for (;;)
    {
        cpu_step(cpu);
    }

    return 0;
}
