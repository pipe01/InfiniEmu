#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "commander.h"
#include "config.h"
#include "pinetime.h"
#include "gdb.h"
#include "ie_time.h"
#include "pcap.h"
#include "program.h"
#include "segger_rtt.h"
#include "util.h"
#include "peripherals/nrf52832/radio.h"

void commander_output(const char *msg, void *userdata)
{
    fwrite(msg, 1, strlen(msg), stdout);
}

int main(int argc, char **argv)
{
    memory_map_t *map = memory_map_new();

    memory_map_add_region(map, memreg_new_simple(0x4001A000, NULL, 100));
    memory_map_add_region(map, memreg_new_simple(0x4000D000, NULL, 100));
    memory_map_add_region(map, memreg_new_simple(0xE0001000, NULL, 200));

    char *program_path = NULL;
    bool run_gdb = false;
    char *runlog_path = NULL;
    bool big_ram = false;
    char *state_path = NULL;

    int c;

    const char *optstring = "bdf:s:"
#if ENABLE_RUNLOG
                            "l:"
#endif
        ;

    while ((c = getopt(argc, argv, optstring)) != -1)
    {
        switch (c)
        {
        case 'f':
            program_path = optarg;
            break;

        case 'd':
            run_gdb = true;
            break;

#if ENABLE_RUNLOG
        case 'l':
            runlog_path = optarg;
            break;
#endif

        case 'b':
            big_ram = true;
            break;

        case 's':
            state_path = optarg;
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

    size_t fsize;
    uint8_t *program_data = read_file_u8(program_path, &fsize);
    if (program_data == NULL)
        return -1;

    program_t *program = program_new(big_ram ? 0x800000 : NRF52832_FLASH_SIZE);
    if (!program_load_elf(program, 0, program_data, fsize))
        program_load_binary(program, 0, program_data, fsize);

    printf("Loaded %ld bytes from %s\n", fsize, program_path);

    pinetime_t *pt = pinetime_new(program);

    NRF52832_t *nrf = pinetime_get_nrf52832(pt);
    cpu_t *cpu = nrf52832_get_cpu(nrf);

    (void)cpu;

#if ENABLE_SEGGER_RTT
    rtt_t *rtt = rtt_new(cpu_mem(cpu));
    bool found_rtt = false;
    size_t rtt_counter = 0, rtt_read = 0;
    char rtt_buffer[1024];
#endif

#if ENABLE_RUNLOG
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

        runlog_record_load_program(runlog, program);

        cpu_set_runlog(cpu, runlog);
        cpu_reset(cpu);
    }
#else
    (void)runlog_path;
#endif

    pcap_t *pcap = pcap_create("bluetooth.pcap");
    radio_set_pcap(nrf52832_get_peripheral(nrf, INSTANCE_RADIO), pcap);

    if (state_path)
    {
        size_t state_size;
        uint8_t *state = read_file_u8(state_path, &state_size);
        if (state)
        {
            if (pinetime_load_state(pt, state, state_size))
                printf("Loaded state from state.bin\n");
            else
                printf("Failed to load state from state.bin\n");
            free(state);
        }
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
        time_use_real_time(false);

#if ENABLE_MEASUREMENT
        uint64_t start, now;
        uint64_t cycles_counter = 0;
        size_t perf_counter = 0;
        start = microseconds_now_real();
#endif

        size_t inst_counter = 0;

        for (;;)
        {
            pinetime_step(pt);

            if (inst_counter++ % 60 == 0)
                time_increment_fake_microseconds(1);

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
            if (++perf_counter == 10000000)
            {
                now = microseconds_now_real();

                uint64_t elapsed = now - start;
                uint64_t elapsed_cycles = nrf52832_get_cycle_counter(nrf) - cycles_counter;
                cycles_counter = nrf52832_get_cycle_counter(nrf);

                start = now;

                printf("Cycles per second: %.0f, target: %d\n", (1000000.f / elapsed) * elapsed_cycles, NRF52832_HFCLK_FREQUENCY);

                perf_counter = 0;
            }
#endif
        }
    }

#if ENABLE_RUNLOG
    if (runlog)
        runlog_free(runlog);
#endif

    return 0;
}
