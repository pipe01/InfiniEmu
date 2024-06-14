#include "peripherals/nrf52832/nvmc.h"

#include "byte_util.h"

typedef union
{
    struct
    {
        unsigned int wen : 1;
        unsigned int een : 1;
    };
    uint32_t value;
} config_t;

struct NVMC_inst_t
{
    uint8_t *data;
    size_t size;

    config_t config;
};

OPERATION(nvmc)
{
    NVMC_t *nvmc = userdata;

    if (op == OP_RESET)
    {
        nvmc->config.value = 0;
        return MEMREG_RESULT_OK;
    }

    if (base == 0 && offset <= nvmc->size)
    {
        if (OP_IS_READ(op))
        {
            switch (op)
            {
            case OP_READ_BYTE:
                *value = nvmc->data[offset];
                break;

            case OP_READ_HALFWORD:
                *value = READ_UINT16(nvmc->data, offset);
                break;

            case OP_READ_WORD:
                *value = READ_UINT32(nvmc->data, offset);
                break;

            default:
                return MEMREG_RESULT_INVALID_SIZE;
            }
        }
        else
        {
            OP_ASSERT_SIZE(op, WORD);

            assert(nvmc->config.wen);
            nvmc->data[offset] &= *value;
        }

        return MEMREG_RESULT_OK;
    }

    switch (offset)
    {
    case 0x400: // READY
        OP_ASSERT_READ(op);
        *value = 1; // Always ready
        return MEMREG_RESULT_OK;

    case 0x504: // CONFIG
        OP_RETURN_REG(nvmc->config.value, WORD);

    default:
        break;
    }

    return MEMREG_RESULT_UNHANDLED;
}

NRF52_PERIPHERAL_CONSTRUCTOR(NVMC, nvmc, uint8_t *data, size_t size)
{
    NVMC_t *nvmc = malloc(sizeof(NVMC_t));
    nvmc->data = data;
    nvmc->size = size;
    return nvmc;
}
