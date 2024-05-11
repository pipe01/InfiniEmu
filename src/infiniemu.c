#define _POSIX_C_SOURCE 2

#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>

#include "config.h"
#include "nrf52832.h"
#include "gdb.h"

#include "components/spi/spinorflash.h"

#ifdef ENABLE_SEGGER_RTT
#include "segger_rtt.h"
#endif

int main(int argc, char **argv)
{
    char *program_path = NULL;
    bool run_gdb = false;
    char *runlog_path = NULL;

    int c;

    while ((c = getopt(argc, argv, "df:l:")) != -1)
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

    uint8_t *program = malloc(fsize);
    fread(program, fsize, 1, f);
    fclose(f);

    printf("Loaded %ld bytes from %s\n", fsize, program_path);

    NRF52832_t *nrf = nrf52832_new(program, fsize);

    spi_add_slave(nrf52832_get_spi(nrf), spinorflash_new(4 * 1024 * 1024, 4 * 1024, 5));

#ifdef ENABLE_SEGGER_RTT
    rtt_t *rtt = rtt_new(cpu_mem(nrf52832_get_cpu(nrf)));
    size_t rtt_counter = 0;
#endif

    if (runlog_path)
    {
        FILE *f = fopen(runlog_path, "wb");
        if (f == NULL)
        {
            fprintf(stderr, "Failed to create runlog file\n");
            return -1;
        }

        runlog_t *runlog = runlog_new(fileno(f));

        runlog_record_load_program(runlog, program, fsize);

        cpu_t *cpu = nrf52832_get_cpu(nrf);
        cpu_set_runlog(cpu, runlog);
        cpu_reset(cpu);
    }

    free(program);

    if (run_gdb)
    {
        printf("Waiting for GDB connection...\n");

        gdb_t *gdb = gdb_new(nrf, true);
        gdb_start(gdb);

        return 0;
    }

#ifdef ENABLE_MEASUREMENT
    struct timeval tv_start, tv_now;
    gettimeofday(&tv_start, NULL);

    size_t inst_counter = 0;
#endif

    for (;;)
    {
        nrf52832_step(nrf);

#ifdef ENABLE_MEASUREMENT
        if (++inst_counter == 1000000)
        {
            gettimeofday(&tv_now, NULL);

            long elapsed = (tv_now.tv_sec - tv_start.tv_sec) * 1000000 + (tv_now.tv_usec - tv_start.tv_usec);

            tv_start = tv_now;

            printf("Elapsed: %lu us\n", elapsed);
            printf("Instructions %lu\n", inst_counter);
            printf("\n");

            inst_counter = 0;
        }
#endif

#ifdef ENABLE_SEGGER_RTT
        if ((rtt_counter++ % 2000) == 0)
        {
            rtt_find_control(rtt);
            rtt_flush_buffers(rtt);
        }
#endif
    }

    return 0;
}
