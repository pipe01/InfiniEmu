#define _POSIX_C_SOURCE 2

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>

#include <capstone/capstone.h>

int main(int argc, char **argv) {
    char *program_path = NULL;
    int c;
    
    while ((c = getopt(argc, argv, "p:")) != -1) {
        switch (c) {
            case 'p':
                program_path = optarg;
                break;
            default:
                return -1;
        }
    }

    if (program_path == NULL) {
        fprintf(stderr, "Usage: %s -p <program_path>\n", argv[0]);
        return -1;
    }

    FILE *f = fopen(program_path, "rb");
    if (f == NULL) {
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

    csh handle;

    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS, &handle) != CS_ERR_OK)
        return -1;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn *inst;

    size_t count = cs_disasm(handle, buffer, fsize, 0, 0, &inst);
    if (count == 0) {
        fprintf(stderr, "Failed to disassemble %s\n", program_path);
        return -1;
    }

    printf("Disassembled %ld instructions\n", count);

    return 0;
}
