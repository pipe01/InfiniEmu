#include "commander.h"

#include <string.h>

#define END            \
    {                  \
        .is_end = true \
    }

typedef struct command_t
{
    bool is_end;

    const char *name;
    const char *description;
    const struct command_t *children;

    void (*handler)(commander_t *cder, const char *cmd, char *args);
} command_t;

struct commander_t
{
    pinetime_t *pt;

    commander_output_t output;
    void *output_userdata;
};

static void commander_output(commander_t *cder, const char *msg)
{
    if (cder->output)
        cder->output(msg, cder->output_userdata);
}

static void commander_outputf(commander_t *cder, const char *fmt, ...)
{
    if (cder->output)
    {
        char buf[256];

        va_list args;
        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);

        cder->output(buf, cder->output_userdata);
    }
}

#define GET_PINS(cder) nrf52832_get_pins(pinetime_get_nrf52832((cder)->pt))

static int parse_pin(const char *args)
{
    char *end;
    int pin = strtol(args, &end, 0);

    if (end == args || *end != '\0' || pin < 0 || pin >= PINS_COUNT)
    {
        return -1;
    }

    return pin;
}

#define COMMAND(name) static void name(commander_t *cder, const char *cmd, char *args)

COMMAND(cmd_help);

COMMAND(cmd_nrf52_pins_set)
{
    int pin = parse_pin(args);

    if (pin < 0)
    {
        commander_outputf(cder, "Invalid pin number: %s\n", args);
        return;
    }

    pins_set(GET_PINS(cder), pin);
}

COMMAND(cmd_nrf52_pins_clear)
{
    int pin = parse_pin(args);

    if (pin < 0)
    {
        commander_outputf(cder, "Invalid pin number: %s\n", args);
        return;
    }

    pins_clear(GET_PINS(cder), pin);
}

COMMAND(cmd_nrf52_pins_toggle)
{
    int pin = parse_pin(args);

    if (pin < 0)
    {
        commander_outputf(cder, "Invalid pin number: %s\n", args);
        return;
    }

    pins_toggle(GET_PINS(cder), pin);
}

COMMAND(cmd_nrf52_pins_read)
{
    pins_t *pins = GET_PINS(cder);

    if (!args)
    {
        char word[PINS_COUNT + 2];
        word[PINS_COUNT] = '\n';
        word[PINS_COUNT + 1] = '\0';

        for (size_t i = 0; i < PINS_COUNT; i++)
        {
            word[i] = pins_is_set(pins, i) ? '1' : '0';
        }

        commander_output(cder, word);
    }
    else
    {
        int pin = parse_pin(args);

        if (pin < 0)
        {
            commander_outputf(cder, "Invalid pin number: %s\n", args);
            return;
        }

        commander_outputf(cder, "%d\n", pins_is_set(pins, pin));
    }
}

COMMAND(cmd_step)
{
    pinetime_step(cder->pt);
}

static command_t commands[] = {
    {
        .name = "help",
        .handler = cmd_help,
    },
    {
        .name = "nrf52",
        .children = (command_t[]){
            {
                .name = "pins",
                .children = (command_t[]){
                    {
                        .name = "set",
                        .handler = cmd_nrf52_pins_set,
                    },
                    {
                        .name = "clear",
                        .handler = cmd_nrf52_pins_clear,
                    },
                    {
                        .name = "toggle",
                        .handler = cmd_nrf52_pins_toggle,
                    },
                    {
                        .name = "read",
                        .handler = cmd_nrf52_pins_read,
                        .description = "Read the state of a pin, or all pins if none is passed as argument",
                    },
                    END,
                },
            },
            END,
        },
    },
    {
        .name = "step",
        .handler = cmd_step,
        .description = "Step the emulator by one instruction",
    },
    END,
};

static void print_commands(commander_t *cder, const command_t *commands, const char *prefix)
{
    for (size_t i = 0; !commands[i].is_end; i++)
    {
        if (commands[i].handler)
        {
            commander_outputf(cder, "%s%s\n", prefix, commands[i].name);

            if (commands[i].description)
                commander_outputf(cder, "  %s\n", commands[i].description);
        }

        if (commands[i].children)
        {
            char *new_prefix = malloc(strlen(prefix) + strlen(commands[i].name) + 2);
            sprintf(new_prefix, "%s%s.", prefix, commands[i].name);

            print_commands(cder, commands[i].children, new_prefix);

            free(new_prefix);
        }
    }
}

COMMAND(cmd_help)
{
    print_commands(cder, commands, "");
}

commander_t *commander_new(pinetime_t *pt)
{
    commander_t *cder = malloc(sizeof(commander_t));
    cder->pt = pt;

    return cder;
}

void commander_free(commander_t *cder)
{
    free(cder);
}

void commander_set_output(commander_t *cder, commander_output_t fn, void *userdata)
{
    cder->output = fn;
    cder->output_userdata = userdata;
}

static const command_t *find_command(const command_t *commands, const char *name)
{
    char *dup = strdup(name);
    char *strtok_save;

    char *first_part = strtok_r(dup, ".", &strtok_save);
    char *rest = strtok_r(NULL, "\0", &strtok_save);

    const command_t *ret = NULL;

    for (size_t i = 0; !commands[i].is_end; i++)
    {
        if (strcmp(commands[i].name, first_part) == 0)
        {
            if (rest == NULL)
            {
                ret = &commands[i];
                break;
            }
            else
            {
                ret = find_command(commands[i].children, rest);
                break;
            }
        }
    }

    free(dup);
    return ret;
}

void commander_run_command(commander_t *cder, const char *command)
{
    char *dup = strdup(command);
    char *strtok_save;

    char *cmd_name = strtok_r(dup, " ", &strtok_save);
    char *cmd_args = strtok_r(NULL, "\0", &strtok_save);

    const command_t *cmd = find_command(commands, cmd_name);

    if (!cmd)
    {
        fprintf(stderr, "Command not found: %s\n", cmd_name);
    }
    else if (!cmd->handler)
    {
        fprintf(stderr, "Command has no handler: %s\n", cmd_name);
    }
    else
    {
        cmd->handler(cder, cmd_name, cmd_args);
    }

    free(dup);
}
