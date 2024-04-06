#include "gdb.h"

#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>

#include "libgdbstub/libgdbstub.h"

typedef struct
{
    int fd;
    NRF52832_t *nrf;
} gdbstub;

static size_t io_peek(GDBSTUBCTX hGdbStubCtx, void *pvUser)
{
    (void)hGdbStubCtx;

    gdbstub *pStub = (gdbstub *)pvUser;
    int cbAvail = 0;
    int rc = ioctl(pStub->fd, FIONREAD, &cbAvail);
    if (rc)
        return 0;

    return cbAvail;
}

static int io_read(GDBSTUBCTX hGdbStubCtx, void *pvUser, void *pvDst, size_t cbRead, size_t *pcbRead)
{
    (void)hGdbStubCtx;

    gdbstub *pStub = (gdbstub *)pvUser;
    ssize_t cbRet = recv(pStub->fd, pvDst, cbRead, MSG_DONTWAIT);
    if (cbRet > 0)
    {
        *pcbRead = cbRead;
        return GDBSTUB_INF_SUCCESS;
    }

    if (!cbRet)
        return GDBSTUB_ERR_PEER_DISCONNECTED;

    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return GDBSTUB_INF_TRY_AGAIN;

    return GDBSTUB_ERR_INTERNAL_ERROR; /** @todo Better status codes for the individual errors. */
}

static int io_write(GDBSTUBCTX hGdbStubCtx, void *pvUser, const void *pvPkt, size_t cbPkt)
{
    (void)hGdbStubCtx;

    gdbstub *pStub = (gdbstub *)pvUser;
    ssize_t cbRet = send(pStub->fd, pvPkt, cbPkt, 0);
    if (cbRet >= 0 && (size_t)cbRet == cbPkt)
        return GDBSTUB_INF_SUCCESS;

    return GDBSTUB_ERR_INTERNAL_ERROR; /** @todo Better status codes for the individual errors. */
}

static int io_poll(GDBSTUBCTX hGdbStubCtx, void *pvUser)
{
    (void)hGdbStubCtx;
    gdbstub *pStub = (gdbstub *)pvUser;
    struct pollfd pollfd;

    pollfd.fd = pStub->fd;
    pollfd.events = POLLIN | POLLHUP | POLLERR;
    pollfd.revents = 0;

    int rc = GDBSTUB_INF_SUCCESS;
    for (;;)
    {
        int rcPsx = poll(&pollfd, 1, INT32_MAX);
        if (rcPsx == 1)
            break; /* Stop polling if the single descriptor has events. */
        if (rcPsx == -1)
            rc = GDBSTUB_ERR_INTERNAL_ERROR; /** @todo Better status codes for the individual errors. */
    }

    return rc;
}

const GDBSTUBIOIF gdbstub_io_if = {
    .pfnPeek = io_peek,
    .pfnRead = io_read,
    .pfnWrite = io_write,
    .pfnPoll = io_poll,
};

const GDBSTUBREG gdbstub_regs[] = {
    {"r0", 32, GDBSTUBREGTYPE_GP},
    {"r1", 32, GDBSTUBREGTYPE_GP},
    {"r2", 32, GDBSTUBREGTYPE_GP},
    {"r3", 32, GDBSTUBREGTYPE_GP},
    {"r4", 32, GDBSTUBREGTYPE_GP},
    {"r5", 32, GDBSTUBREGTYPE_GP},
    {"r6", 32, GDBSTUBREGTYPE_GP},
    {"r7", 32, GDBSTUBREGTYPE_GP},
    {"r8", 32, GDBSTUBREGTYPE_GP},
    {"r9", 32, GDBSTUBREGTYPE_GP},
    {"r10", 32, GDBSTUBREGTYPE_GP},
    {"r11", 32, GDBSTUBREGTYPE_GP},
    {"r12", 32, GDBSTUBREGTYPE_GP},
    {"sp", 32, GDBSTUBREGTYPE_STACK_PTR},
    {"lr", 32, GDBSTUBREGTYPE_CODE_PTR},
    {"pc", 32, GDBSTUBREGTYPE_PC},
    // {"cpsr", 32, GDBSTUBREGTYPE_STATUS},
    {NULL, 0, GDBSTUBREGTYPE_INVALID},
};

int gdbstubcmd_help(GDBSTUBCTX hGdbStubCtx, PCGDBSTUBOUTHLP pHlp, const char *pszArgs, void *pvUser)
{
    pHlp->pfnPrintf(pHlp, "Test: %s %p %#x\n", "help", pHlp, 0xdeadbeef);
    return GDBSTUB_INF_SUCCESS;
}

const GDBSTUBCMD gdbstub_cmds[] = {
    {"help", "Print help", gdbstubcmd_help},
    {NULL, NULL, NULL},
};

void *gdbstub_memalloc(GDBSTUBCTX hGdbStubCtx, void *pvUser, size_t cb)
{
    return malloc(cb);
}

void gdbstub_memfree(GDBSTUBCTX hGdbStubCtx, void *pvUser, void *pv)
{
    free(pv);
}

GDBSTUBTGTSTATE gdbstub_targetGetState(GDBSTUBCTX hGdbStubCtx, void *pvUser)
{
    return GDBSTUBTGTSTATE_RUNNING;
}

int gdbstub_targetMemRead(GDBSTUBCTX hGdbStubCtx, void *pvUser, GDBTGTMEMADDR GdbTgtMemAddr, void *pvDst, size_t cbRead)
{
    gdbstub *stub = (gdbstub *)pvUser;
    NRF52832_t *nrf = stub->nrf;

    cpu_t *cpu = nrf52832_get_cpu(nrf);

    for (size_t i = 0; i < cbRead; i++)
    {
        uint8_t value = cpu_mem_read(cpu, GdbTgtMemAddr + i);

        ((uint8_t *)pvDst)[i] = value;
    }

    return GDBSTUB_INF_SUCCESS;
}

int gdbstub_targetRegsRead(GDBSTUBCTX hGdbStubCtx, void *pvUser, uint32_t *paRegs, uint32_t cRegs, void *pvDst)
{
    gdbstub *stub = (gdbstub *)pvUser;
    uint32_t *u32regs = (uint32_t *)pvDst;

    cpu_t *cpu = nrf52832_get_cpu(stub->nrf);

    if (cRegs != 16)
        return GDBSTUB_ERR_INVALID_PARAMETER;

    u32regs[0] = cpu_reg_read(cpu, ARM_REG_R0);
    u32regs[1] = cpu_reg_read(cpu, ARM_REG_R1);
    u32regs[2] = cpu_reg_read(cpu, ARM_REG_R2);
    u32regs[3] = cpu_reg_read(cpu, ARM_REG_R3);
    u32regs[4] = cpu_reg_read(cpu, ARM_REG_R4);
    u32regs[5] = cpu_reg_read(cpu, ARM_REG_R5);
    u32regs[6] = cpu_reg_read(cpu, ARM_REG_R6);
    u32regs[7] = cpu_reg_read(cpu, ARM_REG_R7);
    u32regs[8] = cpu_reg_read(cpu, ARM_REG_R8);
    u32regs[9] = cpu_reg_read(cpu, ARM_REG_R9);
    u32regs[10] = cpu_reg_read(cpu, ARM_REG_R10);
    u32regs[11] = cpu_reg_read(cpu, ARM_REG_R11);
    u32regs[12] = cpu_reg_read(cpu, ARM_REG_R12);
    u32regs[13] = cpu_reg_read(cpu, ARM_REG_SP);
    u32regs[14] = cpu_reg_read(cpu, ARM_REG_LR);
    u32regs[15] = cpu_reg_read(cpu, ARM_REG_PC);

    return GDBSTUB_INF_SUCCESS;
}

const GDBSTUBIF gdbstub_if = {
    .enmArch = GDBSTUBTGTARCH_ARM,
    .paRegs = gdbstub_regs,
    .pfnMemAlloc = gdbstub_memalloc,
    .pfnMemFree = gdbstub_memfree,
    .pfnTgtGetState = gdbstub_targetGetState,
    .pfnTgtStop = NULL,
    .pfnTgtRestart = NULL,
    .pfnTgtKill = NULL,
    .pfnTgtStep = NULL,
    .pfnTgtCont = NULL,
    .pfnTgtMemRead = gdbstub_targetMemRead,
    .pfnTgtMemWrite = NULL,
    .pfnTgtRegsRead = gdbstub_targetRegsRead,
    .pfnTgtRegsWrite = NULL,
    .pfnTgtTpSet = NULL,
    .pfnTgtTpClear = NULL,
    .pfnMonCmd = NULL,
};

void *gdb_thread(void *arg)
{
    NRF52832_t *nrf52832 = (NRF52832_t *)arg;

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
            .nrf = nrf52832,
        };
        GDBSTUBCTX stub_ctx = NULL;

        int rc = GDBStubCtxCreate(&stub_ctx, &gdbstub_io_if, &gdbstub_if, &stub);
        if (rc == GDBSTUB_INF_SUCCESS)
        {
            GDBStubCtxRun(stub_ctx);
            GDBStubCtxDestroy(stub_ctx);
        }
    }

    return NULL;
}

void gdb_start(NRF52832_t *nrf52832)
{
    pthread_t thread;

    pthread_create(&thread, NULL, gdb_thread, nrf52832);
    pthread_join(thread, NULL);
}