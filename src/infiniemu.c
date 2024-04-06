#define _POSIX_C_SOURCE 2

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <capstone/capstone.h>

#include "cpu.h"
#include "byte_util.h"
#include "incbin.h"

#define NRF52832_SRAM_SIZE 0x10000
#define NRF52832_FLASH_SIZE 0x80000

INCBIN(secret, "../dumps/secret.bin");
INCBIN(ficr, "../dumps/ficr.bin");
INCBIN(uicr, "../dumps/uicr.bin");

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

    uint8_t *flash = malloc(NRF52832_FLASH_SIZE);
    fread(flash, fsize, 1, f);
    fclose(f);
    memset(flash + fsize, 0xFF, NRF52832_FLASH_SIZE - fsize); // 0xFF out the rest of the flash

    printf("Loaded %ld bytes from %s\n", fsize, program_path);

    memreg_t *mem_first = memreg_new_simple(0, flash, NRF52832_FLASH_SIZE);
    memreg_t *last = mem_first;

    uint8_t *sram = malloc(NRF52832_SRAM_SIZE);
    last = last->next = memreg_new_simple(x(2000, 0000), sram, NRF52832_SRAM_SIZE);

    last = last->next = memreg_new_simple_copy(x(F000, 0000), incbin_secret_start, incbin_secret_end - incbin_secret_start);
    last = last->next = memreg_new_simple_copy(x(1000, 0000), incbin_ficr_start, incbin_ficr_end - incbin_ficr_start);
    last = last->next = memreg_new_simple_copy(x(1000, 1000), incbin_uicr_start, incbin_uicr_end - incbin_uicr_start);

    cpu_t *cpu = cpu_new(flash, fsize, mem_first);

    cpu_reset(cpu);

    for (;;)
    {
        cpu_step(cpu);
    }

    return 0;
}
