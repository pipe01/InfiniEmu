#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "commander.h"
#include "config.h"
#include "pinetime.h"
#include "gdb.h"
#include "ie_time.h"
#include "program.h"
#include "segger_rtt.h"

void commander_output(const char *msg, void *userdata)
{
    fwrite(msg, 1, strlen(msg), stdout);
}

int main(int argc, char **argv)
{
    char *program_path = NULL;
    bool run_gdb = false;
    char *runlog_path = NULL;
    bool big_ram = false;

    int c;

    while ((c = getopt(argc, argv, "bdf:l:")) != -1)
    {
        switch (c)
        {
        case 'f':
            program_path = optarg;
            break;

        case 'd':
            run_gdb = true;
            break;

        case 'l':
            runlog_path = optarg;
            break;

        case 'b':
            big_ram = true;
            break;

        default:
            return -1;
        }
    }

    if (program_path == NULL)
    {
        fprintf(stderr, "Usage: %s [-d] [-l <logfile_path>] -f <program_path>\n", argv[0]);
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

    uint8_t *program_data = malloc(fsize);
    fread(program_data, fsize, 1, f);
    fclose(f);

    program_t *program = program_new(big_ram ? 0x800000 : NRF52832_FLASH_SIZE);
    if (!program_load_elf(program, 0, program_data, fsize))
        program_load_binary(program, 0, program_data, fsize);

    printf("Loaded %ld bytes from %s\n", fsize, program_path);

    pinetime_t *pt = pinetime_new(program);

    NRF52832_t *nrf = pinetime_get_nrf52832(pt);
    cpu_t *cpu = nrf52832_get_cpu(nrf);

#if ENABLE_SEGGER_RTT
    rtt_t *rtt = rtt_new(cpu_mem(cpu));
    bool found_rtt = false;
    size_t rtt_counter = 0, rtt_read = 0;
    char rtt_buffer[1024];
#endif

    runlog_t *runlog = NULL;

    if (runlog_path)
    {
        FILE *f = fopen(runlog_path, "wb");
        if (f == NULL)
        {
            fprintf(stderr, "Failed to create runlog file\n");
            return -1;
        }

        runlog = runlog_new(f);

        runlog_record_load_program(runlog, program_data, fsize);

        cpu_set_runlog(cpu, runlog);
        cpu_reset(cpu);
    }

    free(program);

    if (run_gdb)
    {
        printf("Waiting for GDB connection...\n");

        gdb_t *gdb = gdb_new(pt, true);
        gdb_start(gdb);
    }
    else
    {
#if ENABLE_MEASUREMENT
        uint64_t start, now;
        start = microseconds_now();

        size_t inst_counter = 0;
#endif

        for (;;)
        {
            pinetime_step(pt);

#if ENABLE_SEGGER_RTT
            if (found_rtt || rtt_counter < 1000000)
            {
                if (rtt_counter % 1000 == 0)
                {
                    if (!found_rtt)
                        found_rtt = rtt_find_control(rtt);

                    rtt_read = rtt_flush_buffers(rtt, rtt_buffer, sizeof(rtt_buffer));
                    if (rtt_read > 0)
                    {
                        fwrite(rtt_buffer, 1, rtt_read, stdout);
                        fflush(stdout);
                    }
                }

                rtt_counter++;
            }
#endif

#if ENABLE_MEASUREMENT
            if (++inst_counter == 1000000)
            {
                now = microseconds_now();

                uint64_t elapsed = now - start;

                start = now;

                printf("Elapsed: %llu us\n", elapsed);
                printf("Instructions ran: %lu\n", inst_counter);
                printf("Instructions per second: %.0f\n", (1000000.f / elapsed) * inst_counter);
                printf("\n");

                inst_counter = 0;
            }
#endif
        }
    }

    if (runlog)
        runlog_free(runlog);

    return 0;
}
