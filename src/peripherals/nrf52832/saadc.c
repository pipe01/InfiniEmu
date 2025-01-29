#include "peripherals/nrf52832/saadc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "fault.h"
#include "memory.h"
#include "nrf52832.h"
#include "peripherals/nrf52832/easydma.h"
#include "peripherals/nrf52832/ppi.h"

#define CHANNEL_COUNT 8

enum
{
    MODE_SE = 0,
    MODE_DIFF = 1,
};

enum
{
    TASKS_START = 0x000,
    TASKS_SAMPLE = 0x004,
    TASKS_STOP = 0x008,
    TASKS_CALIBRATEOFFSET = 0x00C,
    EVENTS_STARTED = 0x100,
    EVENTS_END = 0x104,
    EVENTS_DONE = 0x108,
    EVENTS_RESULTDONE = 0x10C,
    EVENTS_CALIBRATEDONE = 0x110,
    EVENTS_STOPPED = 0x114,
    EVENTS_CH0_LIMITH = 0x118,
    EVENTS_CH0_LIMITL = 0x11C,
    EVENTS_CH1_LIMITH = 0x120,
    EVENTS_CH1_LIMITL = 0x124,
    EVENTS_CH2_LIMITH = 0x128,
    EVENTS_CH2_LIMITL = 0x12C,
    EVENTS_CH3_LIMITH = 0x130,
    EVENTS_CH3_LIMITL = 0x134,
    EVENTS_CH4_LIMITH = 0x138,
    EVENTS_CH4_LIMITL = 0x13C,
    EVENTS_CH5_LIMITH = 0x140,
    EVENTS_CH5_LIMITL = 0x144,
    EVENTS_CH6_LIMITH = 0x148,
    EVENTS_CH6_LIMITL = 0x14C,
    EVENTS_CH7_LIMITH = 0x150,
    EVENTS_CH7_LIMITL = 0x154,
};

typedef union
{
    struct
    {
        unsigned int STARTED : 1;
        unsigned int END : 1;
        unsigned int DONE : 1;
        unsigned int RESULTDONE : 1;
        unsigned int CALIBRATEDONE : 1;
        unsigned int STOPPED : 1;
        unsigned int CH0_LIMITH : 1;
        unsigned int CH0_LIMITL : 1;
        unsigned int CH1_LIMITH : 1;
        unsigned int CH1_LIMITL : 1;
        unsigned int CH2_LIMITH : 1;
        unsigned int CH2_LIMITL : 1;
        unsigned int CH3_LIMITH : 1;
        unsigned int CH3_LIMITL : 1;
        unsigned int CH4_LIMITH : 1;
        unsigned int CH4_LIMITL : 1;
        unsigned int CH5_LIMITH : 1;
        unsigned int CH5_LIMITL : 1;
        unsigned int CH6_LIMITH : 1;
        unsigned int CH6_LIMITL : 1;
        unsigned int CH7_LIMITH : 1;
        unsigned int CH7_LIMITL : 1;
    };
    uint32_t value;
} inten_t;

typedef union
{
    struct
    {
        unsigned int resp : 2;
        unsigned int : 2;
        unsigned int resn : 2;
        unsigned int : 2;
        unsigned int gain : 3;
        unsigned int : 1;
        unsigned int refsel : 1;
        unsigned int : 3;
        unsigned int tacq : 3;
        unsigned int : 1;
        unsigned int mode : 1;
        unsigned int : 3;
        unsigned int burst : 1;
    };
    uint32_t value;
} channel_cfg_t;

typedef struct
{
    uint32_t pselp, pseln;
    channel_cfg_t config;
    uint32_t limit;
} channel_t;

struct SAADC_inst_t
{
    struct state
    {
        bool enable, running;
        inten_t inten;

        uint32_t resolution;

        channel_t channels[CHANNEL_COUNT];

        easydma_reg_t result;
        int sample_counter;
    };

    pins_t *pins;
    dma_t *dma;
};

static const float gain_table[8] = {
    1.0f / 6.0f,
    1.0f / 5.0f,
    1.0f / 4.0f,
    1.0f / 3.0f,
    1.0f / 2.0f,
    1.0f,
    2.0f,
    4.0f,
};

static const int pins_table[8] = {2, 3, 4, 5, 28, 29, 30, 31};
static const int resolution_table[4] = {8, 10, 12, 14};

static uint16_t read_channel_pin(SAADC_t *saadc, int psel)
{
    assert(psel != 0);

    if (psel == 9) // VDD
        return 3300;

    return pins_get_voltage(saadc->pins, pins_table[psel - 1]);
}

static int16_t get_reading(SAADC_t *saadc, int channel_idx)
{
    channel_t *channel = &saadc->channels[channel_idx];
    assert(channel->pselp != 0);

    float positive = read_channel_pin(saadc, channel->pselp) / 1000.0f;
    float negative = (channel->config.mode == MODE_SE) ? 0 : read_channel_pin(saadc, channel->pseln) / 1000.0f;

    float ref = channel->config.refsel == 0 ? 0.6f : (3.3f / 4);

    int resolution = resolution_table[saadc->resolution];
    if (channel->config.mode != MODE_SE)
        resolution--;

    float result = (positive - negative) * (gain_table[channel->config.gain] / ref) * (1 << resolution);

    return (int16_t)result;
}

static int get_enabled_channels(SAADC_t *saadc)
{
    int enabled = 0;

    for (int i = 0; i < CHANNEL_COUNT; i++)
    {
        if (saadc->channels[i].pselp != 0)
            enabled++;
    }

    return enabled;
}

PPI_TASK_HANDLER(saadc_task_handler)
{
    SAADC_t *saadc = userdata;

    switch (task)
    {
    case TASK_ID(TASKS_START):
        if (!saadc->running)
        {
            printf("SAADC started\n");
            saadc->running = true;
            ppi_fire_event(current_ppi, INSTANCE_SAADC, EVENT_ID(EVENTS_STARTED), saadc->inten.STARTED);
        }
        break;

    case TASK_ID(TASKS_SAMPLE):
        if (saadc->running)
        {
            printf("SAADC sample\n");
            int16_t reading = get_reading(saadc, saadc->sample_counter);
            dma_write(saadc->dma, saadc->result.ptr + (saadc->sample_counter * 2), 2, (uint8_t *)&reading);

            saadc->sample_counter++;
            if (saadc->sample_counter == get_enabled_channels(saadc))
            {
                saadc->result.amount = (get_enabled_channels(saadc) + 1) / 2;
                saadc->sample_counter = 0;

                ppi_fire_event(current_ppi, INSTANCE_SAADC, EVENT_ID(EVENTS_END), saadc->inten.END);
            }
        }
        break;

    case TASK_ID(TASKS_STOP):
        if (saadc->running)
        {
            printf("SAADC stopped\n");
            saadc->running = false;
            ppi_fire_event(current_ppi, INSTANCE_SAADC, EVENT_ID(EVENTS_STOPPED), saadc->inten.STOPPED);
        }
        break;

    case TASK_ID(TASKS_CALIBRATEOFFSET):
        break;
    }
}

OPERATION(saadc)
{
    SAADC_t *saadc = (SAADC_t *)userdata;

    if (op == OP_RESET)
    {
        memset(saadc, 0, sizeof(struct state));
        return MEMREG_RESULT_OK;
    }

    OP_IGNORE_LOAD_DATA
    OP_ASSERT_SIZE(op, WORD);

    printf("read saadc offset 0x%x\n", offset);

    switch (offset)
    {
        OP_TASK(TASKS_START)
        OP_TASK(TASKS_SAMPLE)
        OP_TASK(TASKS_STOP)
        OP_TASK(TASKS_CALIBRATEOFFSET)
        OP_EVENT(EVENTS_STARTED)
        OP_EVENT(EVENTS_END)
        OP_EVENT(EVENTS_DONE)
        OP_EVENT(EVENTS_RESULTDONE)
        OP_EVENT(EVENTS_CALIBRATEDONE)
        OP_EVENT(EVENTS_STOPPED)
        OP_EVENT(EVENTS_CH0_LIMITH)
        OP_EVENT(EVENTS_CH0_LIMITL)
        OP_EVENT(EVENTS_CH1_LIMITH)
        OP_EVENT(EVENTS_CH1_LIMITL)
        OP_EVENT(EVENTS_CH2_LIMITH)
        OP_EVENT(EVENTS_CH2_LIMITL)
        OP_EVENT(EVENTS_CH3_LIMITH)
        OP_EVENT(EVENTS_CH3_LIMITL)
        OP_EVENT(EVENTS_CH4_LIMITH)
        OP_EVENT(EVENTS_CH4_LIMITL)
        OP_EVENT(EVENTS_CH5_LIMITH)
        OP_EVENT(EVENTS_CH5_LIMITL)
        OP_EVENT(EVENTS_CH6_LIMITH)
        OP_EVENT(EVENTS_CH6_LIMITL)
        OP_EVENT(EVENTS_CH7_LIMITH)
        OP_EVENT(EVENTS_CH7_LIMITL)

        OP_INTEN(saadc)
        OP_INTENSET(saadc)
        OP_INTENCLR(saadc)

    case 0x500: // ENABLE
        if (OP_IS_READ(op))
            *value = saadc->enable;
        else
            saadc->enable = *value ? 1 : 0;
        return MEMREG_RESULT_OK;

    case 0x5F0: // RESOLUTION
        OP_RETURN_REG(saadc->resolution, WORD);

    case 0x5F4: // OVERSAMPLE
        if (OP_IS_READ(op))
            *value = 0;
        else if (*value != 0)
            fault_take(FAULT_NOT_IMPLEMENTED);
        return MEMREG_RESULT_OK;

    case 0x62C: // RESULT.PTR
        OP_RETURN_REG(saadc->result.ptr, WORD);

    case 0x630: // RESULT.MAXCNT
        OP_RETURN_REG(saadc->result.maxcnt, WORD);

    case 0x634: // RESULT.AMOUNT
        OP_RETURN_REG(saadc->result.amount, WORD);
    }

    if (offset >= 0x510 && offset <= 0x58C)
    {
        uint32_t ch_idx = (offset - 0x510) / 0x10;
        uint32_t reg_idx = (offset - 0x510) % 0x10;

        switch (reg_idx)
        {
        case 0x0: // CH.PSELP
            if (OP_IS_READ(op))
                *value = saadc->channels[ch_idx].pselp;
            else if (*value != saadc->channels[ch_idx].pselp)
            {
                pins_set_analog(saadc->pins, saadc->channels[ch_idx].pselp, false);
                pins_set_analog(saadc->pins, *value, true);

                saadc->channels[ch_idx].pselp = *value;
            }
            return MEMREG_RESULT_OK;

        case 0x4: // CH.PSELN
            if (OP_IS_READ(op))
                *value = saadc->channels[ch_idx].pseln;
            else if (*value != saadc->channels[ch_idx].pseln)
            {
                pins_set_analog(saadc->pins, saadc->channels[ch_idx].pseln, false);
                pins_set_analog(saadc->pins, *value, true);

                saadc->channels[ch_idx].pseln = *value;
            }
            return MEMREG_RESULT_OK;

        case 0x8: // CH.CONFIG
            OP_RETURN_REG(saadc->channels[ch_idx].config.value, WORD);

        case 0xC: // CH.LIMIT
            OP_RETURN_REG(saadc->channels[ch_idx].limit, WORD);
        }

        return MEMREG_RESULT_OK;
    }

    return MEMREG_RESULT_UNHANDLED;
}

NRF52_PERIPHERAL_CONSTRUCTOR(SAADC, saadc)
{
    SAADC_t *saadc = calloc(1, sizeof(SAADC_t));
    saadc->pins = ctx.pins;
    saadc->dma = ctx.dma;

    ppi_add_peripheral(ctx.ppi, ctx.id, saadc_task_handler, saadc);

    return saadc;
}
