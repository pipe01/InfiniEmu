#include "gdb.h"
#include "byte_util.h"

#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>

#define QUOTE(...) #__VA_ARGS__

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
            <reg name="msp" bitsize="32" type="data_ptr" group="system" regnum="16" />
            <reg name="psp" bitsize="32" type="data_ptr" group="system" regnum="17" />
            <reg name="primask" bitsize="32" type="int" group="system" regnum="18" />
            <reg name="xpsr" bitsize="32" type="int" group="general" regnum="19" />
            <reg name="control" bitsize="32" type="int" group="system" regnum="20" />
            <reg name="basepri" bitsize="32" type="int" group="system" regnum="38" />
            <reg name="faultmask" bitsize="32" type="int" group="system" regnum="39" />
        </feature>
    </target>
);

const char memory_map_xml[] = QUOTE(
    <?xml version="1.0"?>
    <memory-map>
        <memory type="flash" start="0x0" length="0x80000">
            <property name="blocksize">0x1000</property>
        </memory>
        <memory type="flash" start="0x10001000" length="0x400">
            <property name="blocksize">0x400</property>
        </memory>
        <memory type="ram" start="0x20000000" length="0x10000" />
    </memory-map>
);

#define HAS_PREFIX(haystack, needle) (strncmp((needle), (haystack), sizeof(needle) - 1) == 0)
#define SKIP(str) msg += sizeof(str) - 1

#define MAX_BREAKPOINTS 32

bool has_prefix(const char *pre, const char *str)
{
    return strncmp(pre, str, strlen(pre)) == 0;
}

struct gdb_inst_t
{
    NRF52832_t *nrf;

    pthread_cond_t conn_cond;
    pthread_mutex_t conn_lock;
    bool has_connected;

    pthread_cond_t pause_cond;
    pthread_mutex_t pause_lock;
    bool is_paused;

    uint32_t breakpoints[MAX_BREAKPOINTS];
    size_t breakpoint_num;
};

void gdb_set_paused(gdb_t *gdb, bool paused)
{
    pthread_mutex_lock(&gdb->pause_lock);
    gdb->is_paused = paused;
    pthread_cond_signal(&gdb->pause_cond);
    pthread_mutex_unlock(&gdb->pause_lock);
}

void gdb_add_breakpoint(gdb_t *gdb, uint32_t addr)
{
    if (gdb->breakpoint_num >= MAX_BREAKPOINTS)
    {
        printf("Maximum number of breakpoints reached\n");
        return;
    }

    printf("Adding breakpoint at 0x%08x\n", addr);

    gdb->breakpoints[gdb->breakpoint_num++] = addr;
}

void gdb_remove_breakpoint(gdb_t *gdb, uint32_t addr)
{
    printf("Removing breakpoint at 0x%08x\n", addr);

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

typedef struct
{
    int fd;
    gdb_t *gdb;
} gdbstub;

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

    // printf("Sending response to GDB: %s\n", buf);

    write(fd, buf, buf_size);
}

void send_response_str(int fd, const char *text)
{
    size_t len = strlen(text);

    send_response_raw(fd, text, len);
}

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

char *gdb_qSupported(gdbstub *gdb, char *msg)
{
    send_response_str(gdb->fd, "hwbreak+;qXfer:features:read+;qXfer:memory-map:read+");

    return strchr(msg, '#');
}

char *gdb_qXfer(gdbstub *gdb, char *msg)
{
    const char *data;
    size_t data_size;

    if (has_prefix("features:read:target.xml:", msg))
    {
        msg += sizeof("features:read:target.xml:") - 1;

        data = target_xml;
        data_size = sizeof(target_xml) - 1;
    }
    else if (has_prefix("memory-map:read::", msg))
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

char *gdb_queryGeneral(gdbstub *gdb, char *msg)
{
    size_t query_len = (size_t)(strchr(msg, ':') - msg);

    char *rest = msg + query_len + 1;

    if (strncmp(msg, "Supported", query_len) == 0)
        return gdb_qSupported(gdb, rest);
    if (strncmp(msg, "Xfer", query_len) == 0)
        return gdb_qXfer(gdb, rest);

    return NULL;
}

char *gdb_queryHalted(gdbstub *gdb, char *msg)
{
    send_response_str(gdb->fd, "S05");

    return msg + 1;
}

char *gdb_queryReadRegisters(gdbstub *gdb, char *msg)
{
    NRF52832_t *nrf = gdb->gdb->nrf;
    cpu_t *cpu = nrf52832_get_cpu(nrf);

    uint8_t registers[23 * 4];
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
    WRITE_UINT32(registers, 64, cpu_sysreg_read(cpu, ARM_SYSREG_MSP));
    WRITE_UINT32(registers, 68, cpu_sysreg_read(cpu, ARM_SYSREG_PSP));
    WRITE_UINT32(registers, 72, cpu_sysreg_read(cpu, ARM_SYSREG_PRIMASK));
    WRITE_UINT32(registers, 76, cpu_sysreg_read(cpu, ARM_SYSREG_XPSR));
    WRITE_UINT32(registers, 80, cpu_sysreg_read(cpu, ARM_SYSREG_CONTROL));
    WRITE_UINT32(registers, 84, cpu_sysreg_read(cpu, ARM_SYSREG_BASEPRI));
    WRITE_UINT32(registers, 88, cpu_sysreg_read(cpu, ARM_SYSREG_FAULTMASK));

    send_response_bytes(gdb->fd, registers, sizeof(registers));

    return msg + 1;
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

    msg += token + strlen(token) - dup; // Skip numbers

    free(dup);

    uint8_t buf[length];

    for (size_t i = 0; i < length; i++)
    {
        if (!cpu_mem_read(cpu, start + i, buf + i))
        {
            send_response_str(gdb->fd, "E01");
            return msg;
        }
    }

    send_response_bytes(gdb->fd, buf, length);

    return msg;
}

char *gdb_breakpoint(gdbstub *gdb, char *msg)
{
    bool remove = msg[0] == 'z';
    msg++;

    char kind = msg[0];
    msg++;

    if (kind != '1')
    {
        send_response_str(gdb->fd, "E01");
        return strchr(msg, '#');
    }

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

        // printf("Received message from GDB: %s\n", msg);

        while (msg[0] != 0)
        {
            if (msg[0] == '+' || msg[0] == '-')
            {
                // Skip acknowledgement
                msg++;
                continue;
            }
            if (msg[0] == '\x03') // Control+C
            {
                gdb_set_paused(gdb->gdb, true);
                msg++;
                continue;
            }

            if (msg[0] != '$')
            {
                // Invalid message
                printf("Invalid message received from GDB: %s\n", msg);
                return;
            }

            write(gdb->fd, "+", 1);

            msg++;

            char *ret = NULL;

            switch (msg[0])
            {
            case 'q':
                msg++;
                ret = gdb_queryGeneral(gdb, msg);
                break;

            case 'g':
                ret = gdb_queryReadRegisters(gdb, msg);
                break;

            case 'm':
                msg++;
                ret = gdb_queryReadMemory(gdb, msg);
                break;

            case '?':
                ret = gdb_queryHalted(gdb, msg);
                break;

            case 'z':
            case 'Z':
                ret = gdb_breakpoint(gdb, msg);
                break;

            case 'c':
                msg++;
                gdb_set_paused(gdb->gdb, false);

                gdb_wait_for_unpause(gdb->gdb);

                send_response_str(gdb->fd, "S05");
                break;
            }

            if (ret == NULL)
            {
                char *checksum_start = strchr(msg, '#');
                if (checksum_start == NULL)
                {
                    // Invalid message
                    printf("Invalid message received from GDB: %s\n", msg);
                    return;
                }

                msg = checksum_start; // Skip message content
                send_response_str(gdb->fd, "");
                break;
            }

            if (ret[0] != '#')
            {
                // Invalid message
                printf("Invalid message received from GDB: %s\n", msg);
                return;
            }

            msg = ret + 3; // Skip checksum
        }
    }
}

void *gdb_thread(void *arg)
{
    gdb_t *gdb = (gdb_t *)arg;

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
                printf("Port %d is in use, trying next port\n", ntohs(addr.sin_port));
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
        };

        pthread_mutex_lock(&gdb->conn_lock);
        gdb->has_connected = true;
        pthread_cond_signal(&gdb->conn_cond);
        pthread_mutex_unlock(&gdb->conn_lock);

        gdbstub_run(&stub);

        close(client_fd);
    }

    return NULL;
}

gdb_t *gdb_new(NRF52832_t *nrf52832)
{
    gdb_t *gdb = (gdb_t *)malloc(sizeof(gdb_t));
    memset(gdb, 0, sizeof(gdb_t));

    gdb->nrf = nrf52832;
    gdb->is_paused = true;

    pthread_mutex_init(&gdb->conn_lock, NULL);
    pthread_cond_init(&gdb->conn_cond, NULL);

    pthread_mutex_init(&gdb->pause_lock, NULL);
    pthread_cond_init(&gdb->pause_cond, NULL);

    return gdb;
}

void gdb_start(gdb_t *gdb)
{
    pthread_t thread;

    pthread_create(&thread, NULL, gdb_thread, gdb);
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

void gdb_wait_for_unpause(gdb_t *gdb)
{
    pthread_mutex_lock(&gdb->pause_lock);

    while (gdb->is_paused)
    {
        pthread_cond_wait(&gdb->pause_cond, &gdb->pause_lock);
    }

    pthread_mutex_unlock(&gdb->pause_lock);
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

void gdb_check_breakpoint(gdb_t *gdb, uint32_t addr)
{
    if (gdb_has_breakpoint_at(gdb, addr))
    {
        gdb_set_paused(gdb, true);
    }
}
