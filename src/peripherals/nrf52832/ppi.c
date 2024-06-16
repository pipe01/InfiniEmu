#include "peripherals/nrf52832/ppi.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "byte_util.h"
#include "cpu.h"
#include "fault.h"
#include "nrf52832.h"
#include "peripherals/nrf52832/radio.h"
#include "peripherals/nrf52832/rtc.h"
#include "peripherals/nrf52832/timer.h"
#include "peripherals/peripheral.h"

#define CHANNELS_COUNT 32
#define PROGRAMMABLE_CHANNELS_COUNT (CHANNELS_COUNT - 12)

#define PERIPHERALS_COUNT 0x26
#define EVENTS_COUNT 64

_Thread_local PPI_t *current_ppi;

typedef struct
{
    bool enabled, fixed;
    uint8_t eep_peripheral, eep_event;
    uint8_t tep_peripheral, tep_task;
} channel_t;

typedef struct
{
    ppi_task_cb_t cb;
    void *userdata;

    uint64_t events;
} peripheral_t;

struct PPI_t
{
    cpu_t **cpu;

    channel_t channels[CHANNELS_COUNT];
    peripheral_t *peripherals[PERIPHERALS_COUNT];
};

static uint32_t ppi_get_chen(PPI_t *ppi)
{
    uint32_t chen = 0;

    for (size_t i = 0; i < CHANNELS_COUNT; i++)
    {
        if (ppi->channels[i].enabled)
            chen |= (1 << i);
    }

    return chen;
}

OPERATION(ppi)
{
    PPI_t *ppi = (PPI_t *)userdata;

    if (op == OP_RESET)
    {
        for (size_t i = 0; i < PERIPHERALS_COUNT; i++)
        {
            if (ppi->peripherals[i])
                ppi->peripherals[i]->events = 0;
        }

        for (size_t i = 0; i < PROGRAMMABLE_CHANNELS_COUNT; i++)
        {
            memset(&ppi->channels[i], 0, sizeof(channel_t));
        }

        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
    case 0x500: // CHEN
        if (OP_IS_READ(op))
            *value = ppi_get_chen(ppi);
        else
        {
            for (size_t i = 0; i < CHANNELS_COUNT; i++)
            {
                ppi->channels[i].enabled = (*value & (1 << i)) != 0;
            }
        }
        return MEMREG_RESULT_OK;

    case 0x504: // CHENSET
        if (OP_IS_READ(op))
            *value = ppi_get_chen(ppi);
        else
        {
            for (size_t i = 0; i < CHANNELS_COUNT; i++)
            {
                if (*value & (1 << i))
                    ppi->channels[i].enabled = true;
            }
        }
        return MEMREG_RESULT_OK;

    case 0x508: // CHENCLR
        if (OP_IS_READ(op))
            *value = ppi_get_chen(ppi);
        else
        {
            for (size_t i = 0; i < CHANNELS_COUNT; i++)
            {
                if (*value & (1 << i))
                    ppi->channels[i].enabled = false;
            }
        }
        return MEMREG_RESULT_OK;
    }

    if (offset >= 0x510 && offset <= 0x5AC)
    {
        uint32_t idx = (offset - 0x510) / 4;

        if (idx % 2 == 0)
        {
            // CH[n].EEP

            uint32_t chan_idx = idx / 2;

            if (OP_IS_READ(op))
            {
                *value = x(4000, 0100) | (ppi->channels[chan_idx].eep_peripheral << 12) | ppi->channels[chan_idx].eep_event;
            }
            else
            {
                ppi->channels[chan_idx].eep_peripheral = (*value >> 12) & 0xFF;
                ppi->channels[chan_idx].eep_event = *value & 0xFF;
            }
        }
        else
        {
            // CH[n].TEP

            uint32_t chan_idx = (idx - 1) / 2;

            if (OP_IS_READ(op))
            {
                *value = x(4000, 0000) | (ppi->channels[chan_idx].tep_peripheral << 12) | ppi->channels[chan_idx].tep_task;
            }
            else
            {
                ppi->channels[chan_idx].tep_peripheral = (*value >> 12) & 0xFF;
                ppi->channels[chan_idx].tep_task = *value & 0xFF;
            }
        }

        return MEMREG_RESULT_OK;
    }

    return MEMREG_RESULT_UNHANDLED;
}

PPI_t *ppi_new(cpu_t **cpu)
{
    PPI_t *ppi = calloc(1, sizeof(PPI_t));
    ppi->cpu = cpu;

    for (size_t i = PROGRAMMABLE_CHANNELS_COUNT; i < CHANNELS_COUNT; i++)
    {
        ppi->channels[i].fixed = true;
    }

    // TIMER0 COMPARE[0] -> RADIO TXEN
    ppi->channels[20].eep_peripheral = INSTANCE_TIMER0;
    ppi->channels[20].eep_event = EVENT_ID(TIMER_EVENTS_COMPARE0);
    ppi->channels[20].tep_peripheral = INSTANCE_RADIO;
    ppi->channels[20].tep_task = TASK_ID(RADIO_TASKS_TXEN);

    // TIMER0 COMPARE[0] -> RADIO RXEN
    ppi->channels[21].eep_peripheral = INSTANCE_TIMER0;
    ppi->channels[21].eep_event = EVENT_ID(TIMER_EVENTS_COMPARE0);
    ppi->channels[21].tep_peripheral = INSTANCE_RADIO;
    ppi->channels[21].tep_task = TASK_ID(RADIO_TASKS_RXEN);

    // TIMER0 COMPARE[1] -> RADIO DISABLE
    ppi->channels[22].eep_peripheral = INSTANCE_TIMER0;
    ppi->channels[22].eep_event = EVENT_ID(TIMER_EVENTS_COMPARE1);
    ppi->channels[22].tep_peripheral = INSTANCE_RADIO;
    ppi->channels[22].tep_task = TASK_ID(RADIO_TASKS_DISABLE);

    // RADIO BCMATCH -> AAR START
    // TODO: Implement

    // RADIO READY -> CCM KSGEN
    // TODO: Implement

    // RADIO ADDRESS -> CCM CRYPT
    // TODO: Implement

    // RADIO ADDRESS -> TIMER0 CAPTURE[1]
    ppi->channels[26].eep_peripheral = INSTANCE_RADIO;
    ppi->channels[26].eep_event = EVENT_ID(RADIO_EVENTS_ADDRESS);
    ppi->channels[26].tep_peripheral = INSTANCE_TIMER0;
    ppi->channels[26].tep_task = TASK_ID(TIMER_TASKS_CAPTURE1);

    // RADIO END -> TIMER0 CAPTURE[1]
    ppi->channels[27].eep_peripheral = INSTANCE_RADIO;
    ppi->channels[27].eep_event = EVENT_ID(RADIO_EVENTS_END);
    ppi->channels[27].tep_peripheral = INSTANCE_TIMER0;
    ppi->channels[27].tep_task = TASK_ID(TIMER_TASKS_CAPTURE2);

    // RTC0 COMPARE[0] -> RADIO TXEN
    ppi->channels[28].eep_peripheral = INSTANCE_RTC0;
    ppi->channels[28].eep_event = EVENT_ID(RTC_EVENTS_COMPARE0);
    ppi->channels[28].tep_peripheral = INSTANCE_RADIO;
    ppi->channels[28].tep_task = TASK_ID(RADIO_TASKS_TXEN);

    // RTC0 COMPARE[0] -> RADIO RXEN
    ppi->channels[29].eep_peripheral = INSTANCE_RTC0;
    ppi->channels[29].eep_event = EVENT_ID(RTC_EVENTS_COMPARE0);
    ppi->channels[29].tep_peripheral = INSTANCE_RADIO;
    ppi->channels[29].tep_task = TASK_ID(RADIO_TASKS_RXEN);

    // RTC0 COMPARE[0] -> TIMER0 CLEAR
    ppi->channels[30].eep_peripheral = INSTANCE_RTC0;
    ppi->channels[30].eep_event = EVENT_ID(RTC_EVENTS_COMPARE0);
    ppi->channels[30].tep_peripheral = INSTANCE_TIMER0;
    ppi->channels[30].tep_task = TASK_ID(TIMER_TASKS_CLEAR);

    // RTC0 COMPARE[0] -> TIMER0 START
    ppi->channels[31].eep_peripheral = INSTANCE_RTC0;
    ppi->channels[31].eep_event = EVENT_ID(RTC_EVENTS_COMPARE0);
    ppi->channels[31].tep_peripheral = INSTANCE_TIMER0;
    ppi->channels[31].tep_task = TASK_ID(TIMER_TASKS_START);

    return ppi;
}

void ppi_add_peripheral(PPI_t *ppi, uint8_t id, ppi_task_cb_t cb, void *userdata)
{
    assert(id <= PERIPHERALS_COUNT - 1);

    peripheral_t *peripheral = ppi->peripherals[id];

    if (peripheral)
        fault_take(FAULT_PPI_DUPLICATE_PERIPHERAL);

    peripheral = malloc(sizeof(peripheral_t));
    peripheral->cb = cb;
    peripheral->userdata = userdata;

    ppi->peripherals[id] = peripheral;
}

void ppi_remove_peripheral(PPI_t *ppi, uint8_t id)
{
    assert(id < PERIPHERALS_COUNT);

    peripheral_t *peripheral = ppi->peripherals[id];

    if (peripheral)
    {
        free(peripheral);
        ppi->peripherals[id] = NULL;
    }
}

void ppi_fire_task(PPI_t *ppi, uint8_t peripheral_id, uint8_t task_id)
{
    assert(peripheral_id < PERIPHERALS_COUNT);

    peripheral_t *periph = ppi->peripherals[peripheral_id];
    assert(periph != NULL);

    periph->cb(ppi, peripheral_id, task_id, periph->userdata);
}

void ppi_fire_event(PPI_t *ppi, uint8_t peripheral_id, uint8_t event_id, bool pend_exception)
{
    assert(peripheral_id < PERIPHERALS_COUNT);
    assert(event_id < EVENTS_COUNT);

    peripheral_t *periph = ppi->peripherals[peripheral_id];
    assert(periph != NULL);

    // printf("Firing event %d on peripheral %d\n", event_id, peripheral_id);

    periph->events |= (1 << event_id);

    if (pend_exception)
        cpu_exception_set_pending(*ppi->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(peripheral_id));

    for (size_t i = 0; i < CHANNELS_COUNT; i++)
    {
        channel_t *channel = &ppi->channels[i];

        if (channel->enabled && channel->eep_peripheral == peripheral_id && channel->eep_event == event_id)
        {
            ppi_fire_task(ppi, channel->tep_peripheral, channel->tep_task);
        }
    }
}

void ppi_clear_event(PPI_t *ppi, uint8_t peripheral_id, uint8_t event_id)
{
    assert(peripheral_id < PERIPHERALS_COUNT);
    assert(event_id < EVENTS_COUNT);

    peripheral_t *periph = ppi->peripherals[peripheral_id];

    // printf("Clearing event %d on peripheral %d\n", event_id, peripheral_id);

    if (periph)
        periph->events &= ~(1 << event_id);
}

bool ppi_event_is_set(PPI_t *ppi, uint8_t peripheral_id, uint8_t event_id)
{
    assert(peripheral_id < PERIPHERALS_COUNT);
    assert(event_id < EVENTS_COUNT);

    peripheral_t *periph = ppi->peripherals[peripheral_id];

    if (!periph)
        return false;

    return (periph->events & (1 << event_id)) != 0;
}
