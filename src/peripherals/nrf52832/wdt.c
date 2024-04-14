#include "peripherals/nrf52832/wdt.h"

#include <stdlib.h>
#include <string.h>

#include "byte_util.h"

struct WDT_inst_t
{
    uint32_t config;
    uint32_t crv;
    uint32_t rren;

    bool started;
};

OPERATION(wdt)
{
    OP_ASSERT_SIZE(op, WORD);

    WDT_t *wdt = (WDT_t *)userdata;

    switch (offset)
    {
    case 0x000: // TASKS_START
        OP_ASSERT_WRITE(op);

        wdt->started = true;
        return MEMREG_RESULT_OK;

    case 0x504: // CRV
        OP_RETURN_REG(wdt->crv, WORD);

    case 0x508: // RREN
        OP_RETURN_REG(wdt->rren, WORD);

    case 0x50C: // CONFIG
        OP_RETURN_REG(wdt->config, WORD);
    }

    return MEMREG_RESULT_UNHANDLED;
}

WDT_t *wdt_new()
{
    return (WDT_t *)malloc(sizeof(WDT_t));
}

void wdt_reset(WDT_t *wdt)
{
    memset(wdt, 0, sizeof(WDT_t));
}
