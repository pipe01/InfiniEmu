#pragma once

#include <stdint.h>

typedef struct
{
    uint32_t ptr;    // Data pointer
    uint32_t maxcnt; // Maximum number of bytes in buffer
    uint32_t amount; // Number of bytes transferred in the last transaction
    uint32_t list;   // EasyDMA list type
} easydma_reg_t;

#define EASYDMA_CASES(periph) \
    case 0x534: /*RXD.PTR*/ \
        OP_RETURN_REG_RESULT((periph)->rx.ptr, WORD, MEMREG_RESULT_OK_CONTINUE); \
    case 0x538: /*RXD.MAXCNT*/ \
        OP_RETURN_REG_RESULT((periph)->rx.maxcnt, WORD, MEMREG_RESULT_OK_CONTINUE); \
    case 0x540: /*RXD.LIST*/ \
        OP_RETURN_REG_RESULT((periph)->rx.list, WORD, MEMREG_RESULT_OK_CONTINUE); \
    case 0x544: /*TXD.PTR*/ \
        OP_RETURN_REG_RESULT((periph)->tx.ptr, WORD, MEMREG_RESULT_OK_CONTINUE); \
    case 0x548: /*TXD.MAXCNT*/ \
        OP_RETURN_REG_RESULT((periph)->tx.maxcnt, WORD, MEMREG_RESULT_OK_CONTINUE); \
    case 0x550: /*TXD.LIST*/ \
        OP_RETURN_REG_RESULT((periph)->tx.list, WORD, MEMREG_RESULT_OK_CONTINUE);
