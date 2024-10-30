#include "peripherals/nrf52832/gpiote.h"

#include <stdlib.h>
#include <string.h>

#include "nrf52832.h"
#include "peripherals/nrf52832/ppi.h"

enum
{
    TASKS_OUT0 = 0x000,  // Task for writing to pin specified in CONFIG[0].PSEL. Action on pin is configured in CONFIG[0].POLARITY.
    TASKS_OUT1 = 0x004,  // Task for writing to pin specified in CONFIG[1].PSEL. Action on pin is configured in CONFIG[1].POLARITY.
    TASKS_OUT2 = 0x008,  // Task for writing to pin specified in CONFIG[2].PSEL. Action on pin is configured in CONFIG[2].POLARITY.
    TASKS_OUT3 = 0x00C,  // Task for writing to pin specified in CONFIG[3].PSEL. Action on pin is configured in CONFIG[3].POLARITY.
    TASKS_OUT4 = 0x010,  // Task for writing to pin specified in CONFIG[4].PSEL. Action on pin is configured in CONFIG[4].POLARITY.
    TASKS_OUT5 = 0x014,  // Task for writing to pin specified in CONFIG[5].PSEL. Action on pin is configured in CONFIG[5].POLARITY.
    TASKS_OUT6 = 0x018,  // Task for writing to pin specified in CONFIG[6].PSEL. Action on pin is configured in CONFIG[6].POLARITY.
    TASKS_OUT7 = 0x01C,  // Task for writing to pin specified in CONFIG[7].PSEL. Action on pin is configured in CONFIG[7].POLARITY.
    TASKS_SET0 = 0x030,  // Task for writing to pin specified in CONFIG[0].PSEL. Action on pin is to set it high.
    TASKS_SET1 = 0x034,  // Task for writing to pin specified in CONFIG[1].PSEL. Action on pin is to set it high.
    TASKS_SET2 = 0x038,  // Task for writing to pin specified in CONFIG[2].PSEL. Action on pin is to set it high.
    TASKS_SET3 = 0x03C,  // Task for writing to pin specified in CONFIG[3].PSEL. Action on pin is to set it high.
    TASKS_SET4 = 0x040,  // Task for writing to pin specified in CONFIG[4].PSEL. Action on pin is to set it high.
    TASKS_SET5 = 0x044,  // Task for writing to pin specified in CONFIG[5].PSEL. Action on pin is to set it high.
    TASKS_SET6 = 0x048,  // Task for writing to pin specified in CONFIG[6].PSEL. Action on pin is to set it high.
    TASKS_SET7 = 0x04C,  // Task for writing to pin specified in CONFIG[7].PSEL. Action on pin is to set it high.
    TASKS_CLR0 = 0x060,  // Task for writing to pin specified in CONFIG[0].PSEL. Action on pin is to set it low.
    TASKS_CLR1 = 0x064,  // Task for writing to pin specified in CONFIG[1].PSEL. Action on pin is to set it low.
    TASKS_CLR2 = 0x068,  // Task for writing to pin specified in CONFIG[2].PSEL. Action on pin is to set it low.
    TASKS_CLR3 = 0x06C,  // Task for writing to pin specified in CONFIG[3].PSEL. Action on pin is to set it low.
    TASKS_CLR4 = 0x070,  // Task for writing to pin specified in CONFIG[4].PSEL. Action on pin is to set it low.
    TASKS_CLR5 = 0x074,  // Task for writing to pin specified in CONFIG[5].PSEL. Action on pin is to set it low.
    TASKS_CLR6 = 0x078,  // Task for writing to pin specified in CONFIG[6].PSEL. Action on pin is to set it low.
    TASKS_CLR7 = 0x07C,  // Task for writing to pin specified in CONFIG[7].PSEL. Action on pin is to set it low.
    EVENTS_IN0 = 0x100,  // Event generated from pin specified in CONFIG[0].PSEL
    EVENTS_IN1 = 0x104,  // Event generated from pin specified in CONFIG[1].PSEL
    EVENTS_IN2 = 0x108,  // Event generated from pin specified in CONFIG[2].PSEL
    EVENTS_IN3 = 0x10C,  // Event generated from pin specified in CONFIG[3].PSEL
    EVENTS_IN4 = 0x110,  // Event generated from pin specified in CONFIG[4].PSEL
    EVENTS_IN5 = 0x114,  // Event generated from pin specified in CONFIG[5].PSEL
    EVENTS_IN6 = 0x118,  // Event generated from pin specified in CONFIG[6].PSEL
    EVENTS_IN7 = 0x11C,  // Event generated from pin specified in CONFIG[7].PSEL
    EVENTS_PORT = 0x17C, // Event generated from multiple input GPIO pins with SENSE mechanism enabled
};

typedef enum
{
    MODE_DISABLED = 0,
    MODE_EVENT = 1,
    MODE_TASK = 3,
} mode_t;

typedef enum
{
    POLARITY_NONE = 0,
    POLARITY_LOTOHI = 1,
    POLARITY_HITOLO = 2,
    POLARITY_TOGGLE = 3,
} polarity_t;

typedef union
{
    struct
    {
        mode_t MODE : 2;
        unsigned int : 6;
        unsigned int PSEL : 5;
        unsigned int : 3;
        unsigned int POLARITY : 2;
        unsigned int : 2;
        unsigned int OUTINIT : 1;
    };
    uint32_t value;
} config_t;

typedef union
{
    struct
    {
        unsigned int IN0 : 1;
        unsigned int IN1 : 1;
        unsigned int IN2 : 1;
        unsigned int IN3 : 1;
        unsigned int IN4 : 1;
        unsigned int IN5 : 1;
        unsigned int IN6 : 1;
        unsigned int IN7 : 1;
        unsigned int : 23;
        unsigned int PORT : 1;
    };
    uint32_t value;
} inten_t;

struct GPIOTE_inst_t
{
    pins_t *pins;

    inten_t inten;
    config_t config[8];

    uint32_t latch_old;
};

OPERATION(gpiote)
{
    GPIOTE_t *gpiote = userdata;

    if (op == OP_RESET)
    {
        gpiote->inten.value = 0;
        memset(gpiote->config, 0, sizeof(gpiote->config));
        gpiote->latch_old = 0;
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
        OP_TASK(TASKS_OUT0)
        OP_TASK(TASKS_OUT1)
        OP_TASK(TASKS_OUT2)
        OP_TASK(TASKS_OUT3)
        OP_TASK(TASKS_OUT4)
        OP_TASK(TASKS_OUT5)
        OP_TASK(TASKS_OUT6)
        OP_TASK(TASKS_OUT7)
        OP_TASK(TASKS_SET0)
        OP_TASK(TASKS_SET1)
        OP_TASK(TASKS_SET2)
        OP_TASK(TASKS_SET3)
        OP_TASK(TASKS_SET4)
        OP_TASK(TASKS_SET5)
        OP_TASK(TASKS_SET6)
        OP_TASK(TASKS_SET7)
        OP_TASK(TASKS_CLR0)
        OP_TASK(TASKS_CLR1)
        OP_TASK(TASKS_CLR2)
        OP_TASK(TASKS_CLR3)
        OP_TASK(TASKS_CLR4)
        OP_TASK(TASKS_CLR5)
        OP_TASK(TASKS_CLR6)
        OP_TASK(TASKS_CLR7)
        OP_EVENT(EVENTS_IN0)
        OP_EVENT(EVENTS_IN1)
        OP_EVENT(EVENTS_IN2)
        OP_EVENT(EVENTS_IN3)
        OP_EVENT(EVENTS_IN4)
        OP_EVENT(EVENTS_IN5)
        OP_EVENT(EVENTS_IN6)
        OP_EVENT(EVENTS_IN7)
        OP_EVENT(EVENTS_PORT)

        OP_INTENSET(gpiote)
        OP_INTENCLR(gpiote)
    }

    if (offset >= 0x510 && offset <= 0x52C)
    {
        uint32_t n = (offset - 0x510) / 4;

        OP_RETURN_REG(gpiote->config[n].value, WORD);
    }

    return MEMREG_RESULT_UNHANDLED;
}

PPI_TASK_HANDLER(gpiote_task_handler)
{
    GPIOTE_t *gpiote = userdata;

    if (task <= TASK_ID(TASKS_OUT7))
    {
        uint32_t pin = gpiote->config[task - TASK_ID(TASKS_OUT0)].PSEL;

        switch (gpiote->config[task - TASK_ID(TASKS_OUT0)].POLARITY)
        {
        case POLARITY_LOTOHI:
            pins_set(gpiote->pins, pin);
            break;

        case POLARITY_HITOLO:
            pins_clear(gpiote->pins, pin);
            break;

        case POLARITY_TOGGLE:
            pins_toggle(gpiote->pins, pin);
            break;
        }
    }
    else if (task >= TASK_ID(TASKS_SET0) && task <= TASK_ID(TASKS_SET7))
    {
        pins_set(gpiote->pins, gpiote->config[task - TASK_ID(TASKS_SET0)].PSEL);
    }
    else if (task >= TASK_ID(TASKS_CLR0) && task <= TASK_ID(TASKS_CLR7))
    {
        pins_clear(gpiote->pins, gpiote->config[task - TASK_ID(TASKS_CLR0)].PSEL);
    }
}

NRF52_PERIPHERAL_CONSTRUCTOR(GPIOTE, gpiote)
{
    GPIOTE_t *gpiote = malloc(sizeof(GPIOTE_t));
    gpiote->pins = ctx.pins;

    ppi_add_peripheral(current_ppi, ctx.id, gpiote_task_handler, gpiote);

    return gpiote;
}

void gpiote_step(GPIOTE_t *gpiote)
{
    if (!gpiote->inten.PORT)
        return;

    uint32_t new_latch = pins_get_latch(gpiote->pins);

    if (new_latch != gpiote->latch_old)
    {
        gpiote->latch_old = new_latch;

        pins_set_latch(gpiote->pins, 0); // TODO: Should we do this ourselves?

        ppi_fire_event(current_ppi, INSTANCE_GPIOTE, EVENT_ID(EVENTS_PORT), gpiote->inten.PORT);
    }
}
