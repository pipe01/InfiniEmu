#include "gdb.h"
#include "byte_util.h"

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>

#define HAS_PREFIX(haystack, needle) (strncmp((needle), (haystack), sizeof(needle) - 1) == 0)
#define SKIP(str) msg += sizeof(str) - 1

struct gdb_inst_t
{
    NRF52832_t *nrf;
};

typedef struct
{
    int fd;
    gdb_t *gdb;
} gdbstub;

void send_response_text(int fd, const char *text)
{
    size_t len = strlen(text);

    size_t buf_size = len + 4;
    char buf[buf_size + 1];
    buf[buf_size] = 0;

    uint8_t checksum = 0;

    buf[0] = '$';

    for (size_t i = 0; i < len; i++)
    {
        buf[i + 1] = text[i];
        checksum += text[i];
    }

    buf[buf_size - 3] = '#';

    char byte_buf[3];
    snprintf(byte_buf, 3, "%02x", checksum);

    memcpy(buf + buf_size - 2, byte_buf, 2);

    printf("Sending response to GDB: %s\n", buf);

    write(fd, buf, buf_size);
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

    send_response_text(fd, buf);
}

char *gdb_qSupported(gdbstub *gdb, char *msg)
{
    SKIP("qSupported:");

    bool hwbreak = false;

    char *dup = strdup(msg);
    char *token = strtok(dup, ";#");

    while (token)
    {
        // Don't check delimiter on the first token
        if (token != dup && msg[token - dup - 1] == '#')
        {
            msg += token - dup - 1;
            break;
        }

        if (strcmp(token, "hwbreak+") == 0)
            hwbreak = true;

        token = strtok(NULL, ";#");
    }

    free(dup);

    send_response_text(gdb->fd, hwbreak ? "hwbreak+" : "");

    return msg;
}

char *gdb_queryHalted(gdbstub *gdb, char *msg)
{
    send_response_text(gdb->fd, "S05");

    return msg + 1;
}

char *gdb_queryReadRegisters(gdbstub *gdb, char *msg)
{
    NRF52832_t *nrf = gdb->gdb->nrf;
    cpu_t *cpu = nrf52832_get_cpu(nrf);

    uint8_t registers[16 * 4];
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
    WRITE_UINT32(registers, 60, cpu_reg_read(cpu, ARM_REG_PC));
    WRITE_UINT32(registers, 64, cpu_sysreg_read(cpu, ARM_SYSREG_XPSR));

    send_response_bytes(gdb->fd, registers, sizeof(registers));

    return msg + 1;
}

void gdbstub_run(gdbstub *gdb)
{
    char in_buf[4096];
    // char out_buf[4096];
    ssize_t nread;

    char *msg;

    for (;;)
    {
        nread = read(gdb->fd, in_buf, sizeof(in_buf) - 1);
        if (nread <= 0)
            break;

        msg = in_buf;
        msg[nread] = 0;

        printf("Received message from GDB: %s\n", msg);

        while (msg[0] != 0)
        {
            if (msg[0] == '+' || msg[0] == '-')
            {
                // Skip acknowledgement
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

            if (HAS_PREFIX(msg, "qSupported:"))
            {
                msg = gdb_qSupported(gdb, msg);
            }
            else if (msg[0] == '?')
            {
                msg = gdb_queryHalted(gdb, msg);
            }
            else if (msg[0] == 'g')
            {
                msg = gdb_queryReadRegisters(gdb, msg);
            }
            else
            {
                char *checksum_start = strchr(msg, '#');
                if (checksum_start == NULL)
                {
                    // Invalid message
                    printf("Invalid message received from GDB: %s\n", msg);
                    return;
                }

                msg = checksum_start; // Skip message content
                send_response_text(gdb->fd, "");
            }

            if (msg[0] != '#')
            {
                // Invalid message
                printf("Invalid message received from GDB: %s\n", msg);
                return;
            }

            msg += 3; // Skip checksum
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

        gdbstub_run(&stub);

        close(client_fd);
    }

    return NULL;
}

gdb_t *gdb_new(NRF52832_t *nrf52832)
{
    gdb_t *gdb = (gdb_t *)malloc(sizeof(gdb_t));
    gdb->nrf = nrf52832;
    return gdb;
}

void gdb_start(gdb_t *gdb)
{
    pthread_t thread;

    pthread_create(&thread, NULL, gdb_thread, gdb);
    pthread_join(thread, NULL);
}