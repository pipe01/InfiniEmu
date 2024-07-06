#include "byte_util.h"
#include "config.h"
#include "fault.h"
#include "gdb.h"

#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>

#define QUOTE(...) #__VA_ARGS__

#if ENABLE_LOG_GDB
#define LOGF(msg, ...) printf("[GDB] " msg, __VA_ARGS__)
#define LOG(msg) printf("[GDB] " msg "\n")
#else
#define LOGF(...)
#define LOG(msg)
#endif

#define REGISTER_COUNT 24

const char target_xml[] = QUOTE(
    <?xml version="1.0"?>
    <target>
        <feature name="org.gnu.gdb.arm.m-profile">
            <reg name="r0" bitsize="32" type="int" group="general" regnum="0" />
            <reg name="r1" bitsize="32" type="int" group="general" regnum="1" />
            <reg name="r2" bitsize="32" type="int" group="general" regnum="2" />
            <reg name="r3" bitsize="32" type="int" group="general" regnum="3" />
            <reg name="r4" bitsize="32" type="int" group="general" regnum="4" />
            <reg name="r5" bitsize="32" type="int" group="general" regnum="5" />
            <reg name="r6" bitsize="32" type="int" group="general" regnum="6" />
            <reg name="r7" bitsize="32" type="int" group="general" regnum="7" />
            <reg name="r8" bitsize="32" type="int" group="general" regnum="8" />
            <reg name="r9" bitsize="32" type="int" group="general" regnum="9" />
            <reg name="r10" bitsize="32" type="int" group="general" regnum="10" />
            <reg name="r11" bitsize="32" type="int" group="general" regnum="11" />
            <reg name="r12" bitsize="32" type="int" group="general" regnum="12" />
            <reg name="sp" bitsize="32" type="data_ptr" group="general" regnum="13" />
            <reg name="lr" bitsize="32" type="code_ptr" group="general" regnum="14" />
            <reg name="pc" bitsize="32" type="code_ptr" group="general" regnum="15" />
            <reg name="xpsr" bitsize="32" type="int" group="general" regnum="16" />
            <reg name="fpscr" bitsize="32" type="int" group="general" regnum="17" />
            <reg name="msp" bitsize="32" type="data_ptr" group="system" regnum="18" />
            <reg name="psp" bitsize="32" type="data_ptr" group="system" regnum="19" />
            <reg name="primask" bitsize="32" type="int" group="system" regnum="20" />
            <reg name="control" bitsize="32" type="int" group="system" regnum="21" />
            <reg name="basepri" bitsize="32" type="int" group="system" regnum="38" />
            <reg name="faultmask" bitsize="32" type="int" group="system" regnum="39" />
        </feature>
    </target>
);

const char memory_map_xml[] = QUOTE(
    <?xml version="1.0"?>
    <memory-map>
        <memory type="flash" start="0x0" length="0x800000" />
        <memory type="flash" start="0x10001000" length="0x400" />
        <memory type="ram" start="0x20000000" length="0x20000000" />
        <memory type="ram" start="0xe0000000" length="0x40000" />
    </memory-map>
);

#define HAS_PREFIX(haystack, needle) (strncmp((needle), (haystack), sizeof(needle) - 1) == 0)
#define SKIP(str) msg += sizeof(str) - 1

#define MAX_BREAKPOINTS 32

typedef struct
{
    int fd;
    gdb_t *gdb;
    bool noack;
    bool extended;
    bool wants_quit;
} gdbstub;

struct gdb_t
{
    NRF52832_t *nrf;
    pinetime_t *pt;
    gdbstub *current_stub;

    pthread_cond_t conn_cond;
    pthread_mutex_t conn_lock;
    bool has_connected;

    _Atomic bool is_running;
    pthread_t run_thread;
    volatile bool want_break;

    uint32_t breakpoints[MAX_BREAKPOINTS];
    size_t breakpoint_num;
};

void gdb_add_breakpoint(gdb_t *gdb, uint32_t addr)
{
    if (gdb->breakpoint_num >= MAX_BREAKPOINTS)
    {
        LOG("Maximum number of breakpoints reached");
        return;
    }

    LOGF("Adding breakpoint at 0x%08x\n", addr);

    gdb->breakpoints[gdb->breakpoint_num++] = addr;
}

void gdb_remove_breakpoint(gdb_t *gdb, uint32_t addr)
{
    LOGF("Removing breakpoint at 0x%08x\n", addr);

    for (size_t i = 0; i < gdb->breakpoint_num; i++)
    {
        if (gdb->breakpoints[i] == addr)
        {
            gdb->breakpoints[i] = gdb->breakpoints[gdb->breakpoint_num - 1];
            gdb->breakpoint_num--;
            return;
        }
    }
}

void send_response_raw(int fd, const char *data, size_t len)
{
    size_t buf_size = len + 4;

    char buf[buf_size + 1];
    buf[buf_size] = 0;

    uint8_t checksum = 0;

    buf[0] = '$';

    for (size_t i = 0; i < len; i++)
    {
        buf[i + 1] = data[i];
        checksum += data[i];
    }

    buf[buf_size - 3] = '#';

    char byte_buf[3];
    snprintf(byte_buf, 3, "%02x", checksum);

    memcpy(buf + buf_size - 2, byte_buf, 2);

    LOGF("Sending response to GDB: %s\n", buf);

    (void)!write(fd, buf, buf_size);
}

void send_response_str(int fd, const char *text)
{
    size_t len = strlen(text);

    send_response_raw(fd, text, len);
}

#define SEND_RESPONSE_BYTES_LITERAL(fd, data) send_response_bytes(fd, (uint8_t *)(data), sizeof(data) - 1)

void send_response_bytes(int fd, const uint8_t *data, size_t len)
{
    char buf[len * 2 + 1];
    buf[len * 2] = 0;

    char byte_buf[3];

    for (size_t i = 0; i < len; i++)
    {
        snprintf(byte_buf, 3, "%02x", data[i]);
        memcpy(buf + i * 2, byte_buf, 2);
    }

    send_response_str(fd, buf);
}

void send_response_binary(int fd, const uint8_t *data, size_t len)
{
    // When a byte is escaped it takes up two bytes instead of one, therefore the worst case is 2x the original size
    size_t max_size = len * 2;
    char buf[max_size];

    size_t pos = 0;

    for (size_t i = 0; i < len; i++)
    {
        uint8_t b = data[i];

        if (b == '$' || b == '#' || b == '}' || b == '*')
        {
            buf[pos++] = '}';
            buf[pos++] = b ^ 0x20;
        }
        else
        {
            buf[pos++] = b;
        }
    }

    send_response_raw(fd, buf, pos);
}

void parse_hex(const char *str, size_t str_len, uint8_t *data)
{
    for (size_t i = 0; i < str_len; i += 2)
    {
        char byte_str[3];
        memcpy(byte_str, str + i, 2);
        byte_str[2] = 0;

        data[i / 2] = strtol(byte_str, NULL, 16);
    }
}

uint32_t parse_uint32(const char *str)
{
    if (strlen(str) > 2 && str[0] == '0' && str[1] == 'x')
        return strtol(str + 2, NULL, 16);
    else
        return strtol(str, NULL, 10);
}

void mem_watchpoint_cb(cpu_t *cpu, bool isWrite, uint32_t addr, size_t size, uint32_t value_old, uint32_t value_new, void *userdata)
{
    gdb_t *gdb = userdata;

    if (isWrite)
        printf("Hit memory write watchpoint at 0x%08x: old value 0x%08X, new value 0x%08X\n", addr, value_old, value_new);
    else
        printf("Hit memory read watchpoint at 0x%08x: value 0x%08X\n", addr, value_new);

    gdb->want_break = true;
}

void gdb_send_signal(gdbstub *gdb, int signal)
{
    assert(signal >= 0 && signal <= 99);

    char buf[4];
    snprintf(buf, sizeof(buf), "S%02d", signal);

    send_response_str(gdb->fd, buf);
}

char *gdb_qSupported(gdbstub *gdb, char *msg)
{
    send_response_str(gdb->fd, "hwbreak+;qXfer:features:read+;qXfer:memory-map:read+;QStartNoAckMode+");

    return strchr(msg, '#');
}

char *gdb_qXfer(gdbstub *gdb, char *msg)
{
    const char *data;
    size_t data_size;

    if (HAS_PREFIX(msg, "features:read:target.xml:"))
    {
        msg += sizeof("features:read:target.xml:") - 1;

        data = target_xml;
        data_size = sizeof(target_xml) - 1;
    }
    else if (HAS_PREFIX(msg, "memory-map:read::"))
    {
        msg += sizeof("memory-map:read::") - 1;

        data = memory_map_xml;
        data_size = sizeof(memory_map_xml) - 1;
    }
    else
    {
        return NULL;
    }

    size_t start, length;

    char *dup = strdup(msg);

    char *token = strtok(dup, ",");
    if (token == NULL)
    {
        free(dup);
        return NULL;
    }
    start = strtol(token, NULL, 16);

    token = strtok(NULL, "#");
    if (token == NULL)
    {
        free(dup);
        return NULL;
    }
    length = strtol(token, NULL, 16);

    // Skip numbers
    msg += token + strlen(token) - dup;

    free(dup);

    size_t remaining = data_size - start;
    size_t size = remaining > length ? length : remaining;

    uint8_t buf[size + 1];
    buf[0] = size == remaining ? 'l' : 'm';
    memcpy(buf + 1, data + start, size);

    send_response_binary(gdb->fd, buf, sizeof(buf));

    return msg;
}

char *gdb_qSearchMemory(gdbstub *gdb, char *msg)
{
    cpu_t *cpu = nrf52832_get_cpu(gdb->gdb->nrf);

    msg += sizeof("memory:") - 1;

    size_t start, length;

    char *dup = strdup(msg);

    char *token = strtok(dup, ";");
    if (token == NULL)
    {
        free(dup);
        return NULL;
    }
    start = strtol(token, NULL, 16);

    token = strtok(NULL, ";");
    if (token == NULL)
    {
        free(dup);
        return NULL;
    }
    length = strtol(token, NULL, 16);

    msg += token + strlen(token) - dup + 1;

    free(dup);

    char *pattern = msg;
    uint32_t pattern_size = 0;

    do
    {
        pattern_size++;
        msg++;
    } while (*msg != '#');

    uint32_t match_addr = memreg_find_data(cpu_mem(cpu), start, length, (uint8_t *)pattern, pattern_size);
    if (match_addr != MEMREG_FIND_NOT_FOUND)
    {
        char resp[30];
        snprintf(resp, sizeof(resp), "1,%x", match_addr);

        send_response_str(gdb->fd, resp);
    }
    else
    {
        send_response_str(gdb->fd, "0");
    }

    return msg;
}

char *gdb_qCommand(gdbstub *gdb, char *msg)
{
    char *data_end = strchr(msg, '#');
    size_t hex_len = data_end - msg;

    size_t cmd_len = hex_len / 2;
    char command[cmd_len + 1];
    command[cmd_len] = 0;

    parse_hex(msg, hex_len, (uint8_t *)command);

    if (strcmp(command, "reset halt") == 0)
    {
        nrf52832_reset(gdb->gdb->nrf);

        send_response_str(gdb->fd, "OK");
    }
    else if (strcmp(command, "step") == 0)
    {
        nrf52832_step(gdb->gdb->nrf);

        send_response_str(gdb->fd, "OK");
    }
    else if (strcmp(command, "quit") == 0)
    {
        gdb->wants_quit = true;

        send_response_str(gdb->fd, "OK");
    }
    else if (strncmp(command, "reg ", 4) == 0 && cmd_len > 4)
    {
        const char *arg = command + 4;

        if (arg[0] == 's' && cmd_len >= 6)
        {
            long num = strtol(arg + 1, NULL, 10);

            if (num >= 0 && num <= 31)
            {
                uint32_t value = cpu_reg_read(nrf52832_get_cpu(gdb->gdb->nrf), ARM_REG_S0 + num);

                char resp[15];
                int resp_len = snprintf(resp, sizeof(resp), "0x%08x\n", value);

                send_response_bytes(gdb->fd, (uint8_t *)resp, resp_len);
            }
            else
            {
                const char *resp = "Invalid scalar register number\n";
                send_response_bytes(gdb->fd, (uint8_t *)resp, strlen(resp));
            }
        }
        else
        {
            const char *resp = "Invalid register\n";
            send_response_bytes(gdb->fd, (uint8_t *)resp, strlen(resp));
        }
    }
    else if (strncmp(command, "pin ", 4) == 0)
    {
        const char *arg = command + 4;

        long num = strtol(arg, NULL, 10);

        if (num >= 0 && num <= 31)
        {
            pins_t *pins = nrf52832_get_pins(gdb->gdb->nrf);

            pins_toggle(pins, num);

            send_response_str(gdb->fd, "OK");
        }
        else
        {
            const char *resp = "Invalid pin number\n";
            send_response_bytes(gdb->fd, (uint8_t *)resp, strlen(resp));
        }
    }
    else if (strncmp(command, "brmemw ", 7) == 0)
    {
        const char *arg = command + 7;

        uint32_t addr = parse_uint32(arg);

        cpu_set_memory_watchpoint(nrf52832_get_cpu(gdb->gdb->nrf), addr, false, true, mem_watchpoint_cb, gdb->gdb);

        send_response_str(gdb->fd, "OK");
    }
    else
    {
        send_response_str(gdb->fd, "");
    }

    return data_end;
}

char *gdb_queryGeneral(gdbstub *gdb, char *msg)
{
    bool isSet = msg[0] == 'Q';
    msg++;

    if (HAS_PREFIX(msg, "Rcmd,"))
        return gdb_qCommand(gdb, msg + 5);

    size_t query_len = (size_t)(strchr(msg, ':') - msg);

    char *rest = msg + query_len + 1;

    if (strncmp(msg, "Supported", query_len) == 0)
        return gdb_qSupported(gdb, rest);
    if (strncmp(msg, "Xfer", query_len) == 0)
        return gdb_qXfer(gdb, rest);
    if (strncmp(msg, "Search:memory:", query_len) == 0)
        return gdb_qSearchMemory(gdb, rest);

    if (isSet && HAS_PREFIX(msg, "StartNoAckMode"))
    {
        gdb->noack = true;
        send_response_str(gdb->fd, "OK");
        return strchr(msg, '#');
    }

    return NULL;
}

char *gdb_queryHalted(gdbstub *gdb, char *msg)
{
    gdb_send_signal(gdb, SIGTRAP);

    return msg + 1;
}

char *gdb_queryReadRegisters(gdbstub *gdb, char *msg)
{
    NRF52832_t *nrf = gdb->gdb->nrf;
    cpu_t *cpu = nrf52832_get_cpu(nrf);

    uint8_t registers[REGISTER_COUNT * sizeof(uint32_t)];
    WRITE_UINT32(registers, 0, cpu_reg_read(cpu, ARM_REG_R0));
    WRITE_UINT32(registers, 4, cpu_reg_read(cpu, ARM_REG_R1));
    WRITE_UINT32(registers, 8, cpu_reg_read(cpu, ARM_REG_R2));
    WRITE_UINT32(registers, 12, cpu_reg_read(cpu, ARM_REG_R3));
    WRITE_UINT32(registers, 16, cpu_reg_read(cpu, ARM_REG_R4));
    WRITE_UINT32(registers, 20, cpu_reg_read(cpu, ARM_REG_R5));
    WRITE_UINT32(registers, 24, cpu_reg_read(cpu, ARM_REG_R6));
    WRITE_UINT32(registers, 28, cpu_reg_read(cpu, ARM_REG_R7));
    WRITE_UINT32(registers, 32, cpu_reg_read(cpu, ARM_REG_R8));
    WRITE_UINT32(registers, 36, cpu_reg_read(cpu, ARM_REG_R9));
    WRITE_UINT32(registers, 40, cpu_reg_read(cpu, ARM_REG_R10));
    WRITE_UINT32(registers, 44, cpu_reg_read(cpu, ARM_REG_R11));
    WRITE_UINT32(registers, 48, cpu_reg_read(cpu, ARM_REG_R12));
    WRITE_UINT32(registers, 52, cpu_reg_read(cpu, ARM_REG_SP));
    WRITE_UINT32(registers, 56, cpu_reg_read(cpu, ARM_REG_LR));
    WRITE_UINT32(registers, 60, cpu_reg_read(cpu, ARM_REG_PC) - 4);
    WRITE_UINT32(registers, 64, cpu_sysreg_read(cpu, ARM_SYSREG_XPSR));
    WRITE_UINT32(registers, 68, cpu_reg_read(cpu, ARM_REG_FPSCR));
    WRITE_UINT32(registers, 72, cpu_sysreg_read(cpu, ARM_SYSREG_MSP));
    WRITE_UINT32(registers, 76, cpu_sysreg_read(cpu, ARM_SYSREG_PSP));
    WRITE_UINT32(registers, 80, cpu_sysreg_read(cpu, ARM_SYSREG_PRIMASK));
    WRITE_UINT32(registers, 84, cpu_sysreg_read(cpu, ARM_SYSREG_CONTROL));
    WRITE_UINT32(registers, 88, cpu_sysreg_read(cpu, ARM_SYSREG_BASEPRI));
    WRITE_UINT32(registers, 92, cpu_sysreg_read(cpu, ARM_SYSREG_FAULTMASK));

    send_response_bytes(gdb->fd, registers, sizeof(registers));

    return msg;
}

char *gdb_queryWriteRegisters(gdbstub *gdb, char *msg)
{
    size_t len = strlen(msg) - 3; // Don't count trailing checksum
    size_t reg_count = len / 8;

    if (reg_count < 16)
        return NULL;

    NRF52832_t *nrf = gdb->gdb->nrf;
    cpu_t *cpu = nrf52832_get_cpu(nrf);

    uint32_t *registers = (uint32_t *)calloc(reg_count, sizeof(uint32_t));

    parse_hex(msg, len, (uint8_t *)registers);

    for (size_t i = 0; i < reg_count; i++)
    {
        if (i <= 12)
        {
            cpu_reg_write(cpu, ARM_REG_R0 + i, registers[i]);
            continue;
        }

        switch (i)
        {
        case 13:
            cpu_reg_write(cpu, ARM_REG_SP, registers[i]);
            break;
        case 14:
            cpu_reg_write(cpu, ARM_REG_LR, registers[i]);
            break;
        case 15:
            cpu_reg_write(cpu, ARM_REG_PC, registers[i]);
            break;
        case 16:
            cpu_sysreg_write(cpu, ARM_SYSREG_XPSR, registers[i], true);
            break;
        case 17:
            cpu_reg_write(cpu, ARM_REG_FPSCR, registers[i]);
            break;
        case 18:
            cpu_sysreg_write(cpu, ARM_SYSREG_MSP, registers[i], true);
            break;
        case 19:
            cpu_sysreg_write(cpu, ARM_SYSREG_PSP, registers[i], true);
            break;
        case 20:
            cpu_sysreg_write(cpu, ARM_SYSREG_PRIMASK, registers[i], true);
            break;
        case 21:
            cpu_sysreg_write(cpu, ARM_SYSREG_CONTROL, registers[i], true);
            break;
        case 22:
            cpu_sysreg_write(cpu, ARM_SYSREG_BASEPRI, registers[i], true);
            break;
        case 23:
            cpu_sysreg_write(cpu, ARM_SYSREG_FAULTMASK, registers[i], true);
            break;
        }
    }

    free(registers);
    return 0;
}

char *gdb_queryReadMemory(gdbstub *gdb, char *msg)
{
    NRF52832_t *nrf = gdb->gdb->nrf;
    cpu_t *cpu = nrf52832_get_cpu(nrf);

    char *dup = strdup(msg);

    uint32_t start = 0, length = 0;

    char *token = strtok(dup, ",");
    if (token == NULL)
    {
        free(dup);
        return NULL;
    }
    start = strtol(token, NULL, 16);

    token = strtok(NULL, "#");
    if (token == NULL)
    {
        free(dup);
        return NULL;
    }
    length = strtol(token, NULL, 16);

    msg += token - dup + strlen(token); // Skip numbers

    // free(dup); // GCC complains about use after free if this line is added so screw it, here's a memory leak for you

    uint8_t buf[length];

    if (length == 4)
    {
        uint32_t value = memreg_read(cpu_mem(cpu), start);
        memcpy(buf, &value, 4);
    }
    else
    {
        for (size_t i = 0; i < length; i++)
        {
            if (!cpu_mem_read(cpu, start + i, buf + i))
            {
                send_response_str(gdb->fd, "E01");
                return msg;
            }
        }
    }

    send_response_bytes(gdb->fd, buf, length);

    return msg;
}

char *gdb_queryWriteMemory(gdbstub *gdb, char *msg)
{
    NRF52832_t *nrf = gdb->gdb->nrf;
    cpu_t *cpu = nrf52832_get_cpu(nrf);

    char *dup = strdup(msg);

    uint32_t start = 0, length = 0;

    char *token = strtok(dup, ",");
    if (token == NULL)
    {
        free(dup);
        return NULL;
    }
    start = strtol(token, NULL, 16);

    token = strtok(NULL, ":");
    if (token == NULL)
    {
        free(dup);
        return NULL;
    }
    length = strtol(token, NULL, 16);

    msg += token + strlen(token) - dup + 1; // Skip numbers

    // free(dup); // GCC complains about use after free if this line is added so screw it, here's a memory leak for you

    uint8_t data[length];

    parse_hex(msg, length * 2, (uint8_t *)data);

    for (size_t i = 0; i < length; i++)
    {
        cpu_mem_write(cpu, start + i, data[i]);
    }

    send_response_str(gdb->fd, "OK");

    return strchr(msg, '#');
}

char *gdb_breakpoint(gdbstub *gdb, char *msg)
{
    bool remove = msg[0] == 'z';
    msg++;

    char kind = msg[0];
    msg++;

    if (kind != '1')
        return NULL;

    msg++; // Skip comma

    char *dup = strdup(msg);

    char *token = strtok(dup, ",");
    if (token == NULL)
    {
        free(dup);
        return NULL;
    }

    uint32_t addr = strtol(token, NULL, 16);

    free(dup);

    if (remove)
        gdb_remove_breakpoint(gdb->gdb, addr);
    else
        gdb_add_breakpoint(gdb->gdb, addr);

    send_response_str(gdb->fd, "OK");

    return strchr(msg, '#');
}

bool gdb_has_breakpoint_at(gdb_t *gdb, uint32_t addr)
{
    for (size_t i = 0; i < gdb->breakpoint_num; i++)
    {
        if (gdb->breakpoints[i] == addr)
            return true;
    }

    return false;
}

void *gdb_run_cpu(void *userdata)
{
    gdbstub *stub = (gdbstub *)userdata;
    cpu_t *cpu = nrf52832_get_cpu(stub->gdb->nrf);

    jmp_buf fault_jmp;
    bool has_faulted = false;

    if (setjmp(fault_jmp))
    {
        has_faulted = true;
    }
    else
    {
        fault_set_jmp(&fault_jmp);

        while (!stub->gdb->want_break)
        {
            uint32_t pc = cpu_reg_read(cpu, ARM_REG_PC) - 4;

            if (gdb_has_breakpoint_at(stub->gdb, pc))
                break;

            pinetime_step(stub->gdb->pt);
        }
    }

    fault_clear_jmp();

    stub->gdb->want_break = false;
    stub->gdb->is_running = false;
    gdb_send_signal(stub, has_faulted ? SIGABRT : SIGTRAP);

    return NULL;
}

void gdb_continue(gdbstub *gdb)
{
    bool want = false;
    if (!atomic_compare_exchange_strong(&gdb->gdb->is_running, &want, true))
        return;

    pthread_create(&gdb->gdb->run_thread, NULL, gdb_run_cpu, gdb);
}

void gdbstub_run(gdbstub *gdb)
{
    char in_buf[4096];
    ssize_t nread;

    char *msg;

    for (;;)
    {
        nread = read(gdb->fd, in_buf, sizeof(in_buf) - 1);
        if (nread <= 0)
            break;

        msg = in_buf;
        msg[nread] = 0;

        LOGF("Received message from GDB: %s\n", msg);

        while (msg[0] != 0)
        {
            if (msg[0] == '+' || msg[0] == '-')
            {
                // Skip acknowledgement
                msg++;
                continue;
            }
            if (msg[0] == 3) // Control+C
            {
                if (gdb->gdb->is_running)
                {
                    gdb->gdb->want_break = true;
                    pthread_join(gdb->gdb->run_thread, NULL);
                }

                msg++;
                continue;
            }

            if (msg[0] != '$')
            {
                // Invalid message
                LOGF("Invalid message received from GDB: %s\n", msg);
                return;
            }

            if (!gdb->noack)
                (void)!write(gdb->fd, "+", 1);

            msg++;

            char *ret = NULL;

            switch (msg[0])
            {
            case '!':
                ret = msg + 1;
                gdb->extended = true;
                LOG("Extended mode enabled");
                send_response_str(gdb->fd, "OK");
                break;

            case '?':
                ret = gdb_queryHalted(gdb, msg);
                break;

            case 'q':
            case 'Q':
                ret = gdb_queryGeneral(gdb, msg);
                break;

            case 'g':
                msg++;
                ret = gdb_queryReadRegisters(gdb, msg);
                break;

            case 'G':
                msg++;
                ret = gdb_queryWriteRegisters(gdb, msg);
                break;

            case 'm':
                msg++;
                ret = gdb_queryReadMemory(gdb, msg);
                break;

            case 'M':
                msg++;
                ret = gdb_queryWriteMemory(gdb, msg);
                break;

            case 'R':
                LOG("Resetting target");

                ret = strchr(msg, '#');
                pinetime_reset(gdb->gdb->pt);
                break;

            case 's':
                ret = msg + 1;

                // TODO: Catch faults
                pinetime_step(gdb->gdb->pt);
                gdb_send_signal(gdb, SIGTRAP);
                break;

            case 'z':
            case 'Z':
                ret = gdb_breakpoint(gdb, msg);
                break;

            case 'c':
                ret = msg + 1;
                gdb_continue(gdb);
                break;
            }

            if (ret == NULL)
            {
                char *checksum_start = strchr(msg, '#');
                if (checksum_start == NULL)
                {
                    // Invalid message
                    LOGF("Invalid message received from GDB: %s\n", msg);
                    return;
                }

                msg = checksum_start; // Skip message content
                send_response_str(gdb->fd, "");
                break;
            }

            if (ret[0] != '#')
            {
                // Invalid message
                LOGF("Invalid message received from GDB: %s\n", msg);
                return;
            }

            msg = ret + 3; // Skip checksum
        }
    }
}

void gdb_start(gdb_t *gdb)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(3333);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        perror("socket");
        exit(1);
    }

    for (;;)
    {
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            if (errno == EADDRINUSE)
            {
                LOGF("Port %d is in use, trying next port\n", ntohs(addr.sin_port));
                addr.sin_port = htons(ntohs(addr.sin_port) + 1);
                continue;
            }

            perror("bind");
            exit(1);
        }

        printf("GDB stub listening on port %d\n", ntohs(addr.sin_port));
        break;
    }

    for (;;)
    {
        listen(fd, 1);

        int client_fd = accept(fd, NULL, NULL);

        gdbstub stub = {
            .fd = client_fd,
            .gdb = gdb,
            .noack = false,
        };
        gdb->current_stub = &stub;

        pthread_mutex_lock(&gdb->conn_lock);
        gdb->has_connected = true;
        pthread_cond_signal(&gdb->conn_cond);
        pthread_mutex_unlock(&gdb->conn_lock);

        gdbstub_run(&stub);

        gdb->current_stub = NULL;
        close(client_fd);

        if (stub.wants_quit)
            break;
    }
}

gdb_t *gdb_new(pinetime_t *pt, bool start_paused)
{
    gdb_t *gdb = malloc(sizeof(gdb_t));
    memset(gdb, 0, sizeof(gdb_t));

    gdb->nrf = pinetime_get_nrf52832(pt);
    gdb->pt = pt;

    pthread_mutex_init(&gdb->conn_lock, NULL);
    pthread_cond_init(&gdb->conn_cond, NULL);

    return gdb;
}

void gdb_wait_for_connection(gdb_t *gdb)
{
    pthread_mutex_lock(&gdb->conn_lock);

    while (!gdb->has_connected)
    {
        pthread_cond_wait(&gdb->conn_cond, &gdb->conn_lock);
    }

    pthread_mutex_unlock(&gdb->conn_lock);
}
