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
    WDT_t *wdt = (WDT_t *)userdata;

    if (op == OP_RESET)
    {
        memset(wdt, 0, sizeof(WDT_t));
        return MEMREG_RESULT_OK;
    }

    OP_IGNORE_LOAD_DATA
    OP_ASSERT_SIZE(op, WORD);

    // TODO: Make watchdog do something

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

    case 0x600: // RR[0]
        OP_ASSERT_WRITE(op);
        return MEMREG_RESULT_OK;
    }

    return MEMREG_RESULT_UNHANDLED;
}

NRF52_PERIPHERAL_CONSTRUCTOR(WDT, wdt)
{
    WDT_t *wdt = malloc(sizeof(WDT_t));

    state_store_register(ctx.state_store, PERIPHERAL_KEY(ctx.id), wdt, sizeof(WDT_t));

    return wdt;
}
