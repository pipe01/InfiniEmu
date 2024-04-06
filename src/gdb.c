#include "gdb.h"

#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>

struct gdb_inst_t
{
    NRF52832_t *nrf;
};

typedef struct
{
    int fd;
    gdb_t *gdb;
} gdbstub;

void *gdb_thread(void *arg)
{
    gdb_t *gdb = (gdb_t *)arg;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(3333);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        perror("socket");
        exit(1);
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        exit(1);
    }

    for (;;)
    {
        listen(fd, 1);

        int client_fd = accept(fd, NULL, NULL);

        gdbstub stub = {
            .fd = client_fd,
            .gdb = gdb,
        };
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