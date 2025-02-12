#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "commander.h"
#include "config.h"
#include "pinetime.h"
#include "fault.h"
#include "gdb.h"
#include "ie_time.h"
#include "lua.h"
#include "pcap.h"
#include "program.h"
#include "segger_rtt.h"
#include "util.h"
#include "peripherals/nrf52832/radio.h"

void run_emulation(pinetime_t *pt, cpu_t *cpu, NRF52832_t *nrf);

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
    char *lua_script_path = NULL;

    int c;

    const char *optstring = "bdf:s:L:"
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

        case 'L':
            lua_script_path = optarg;
            break;

        default:
            return -1;
        }
    }

    if (lua_script_path)
    {
        run_lua_file(lua_script_path, NULL);
        return 0;
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
    program_load(program, 0, program_data, fsize);

    printf("Loaded %ld bytes from %s\n", fsize, program_path);

    pinetime_t *pt = pinetime_new(program);

    NRF52832_t *nrf = pinetime_get_nrf52832(pt);
    cpu_t *cpu = nrf52832_get_cpu(nrf);

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
        jmp_buf fault_jmp;

        if (setjmp(fault_jmp))
        {
            fprintf(stderr, "R0:  0x%08X\n", cpu_reg_read(cpu, ARM_REG_R0));
            fprintf(stderr, "R1:  0x%08X\n", cpu_reg_read(cpu, ARM_REG_R1));
            fprintf(stderr, "R2:  0x%08X\n", cpu_reg_read(cpu, ARM_REG_R2));
            fprintf(stderr, "R3:  0x%08X\n", cpu_reg_read(cpu, ARM_REG_R3));
            fprintf(stderr, "R4:  0x%08X\n", cpu_reg_read(cpu, ARM_REG_R4));
            fprintf(stderr, "R5:  0x%08X\n", cpu_reg_read(cpu, ARM_REG_R5));
            fprintf(stderr, "R6:  0x%08X\n", cpu_reg_read(cpu, ARM_REG_R6));
            fprintf(stderr, "R7:  0x%08X\n", cpu_reg_read(cpu, ARM_REG_R7));
            fprintf(stderr, "R8:  0x%08X\n", cpu_reg_read(cpu, ARM_REG_R8));
            fprintf(stderr, "R9:  0x%08X\n", cpu_reg_read(cpu, ARM_REG_R9));
            fprintf(stderr, "R10: 0x%08X\n", cpu_reg_read(cpu, ARM_REG_R10));
            fprintf(stderr, "R11: 0x%08X\n", cpu_reg_read(cpu, ARM_REG_R11));
            fprintf(stderr, "R12: 0x%08X\n", cpu_reg_read(cpu, ARM_REG_R12));
            fprintf(stderr, "SP:  0x%08X\n", cpu_reg_read(cpu, ARM_REG_SP));
            fprintf(stderr, "LR:  0x%08X\n", cpu_reg_read(cpu, ARM_REG_LR));
            fprintf(stderr, "PC:  0x%08X\n", cpu_reg_read(cpu, ARM_REG_PC));
            return -1;
        }
        else
        {
            fault_set_jmp(&fault_jmp);

            run_emulation(pt, cpu, nrf);
        }

        fault_clear_jmp();
    }

#if ENABLE_RUNLOG
    if (runlog)
        runlog_free(runlog);
#endif

    return 0;
}

void run_emulation(pinetime_t *pt, cpu_t *cpu, NRF52832_t *nrf)
{
#if ENABLE_SEGGER_RTT
    rtt_t *rtt = rtt_new(cpu_mem(cpu));
    bool found_rtt = false;
    size_t rtt_counter = 0, rtt_read = 0;
    char rtt_buffer[1024];
#endif

#if ENABLE_MEASUREMENT
    uint64_t start, now;
    uint64_t cycles_counter = 0;
    size_t perf_counter = 0;
    start = microseconds_now_real();
#endif

    size_t cycle_counter = 0;

    for (;;)
    {
        cycle_counter += pinetime_step(pt);

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