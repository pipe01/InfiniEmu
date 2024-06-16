#pragma once

#include "pinetime.h"

typedef void (*commander_output_t)(const char *msg, void *userdata);

typedef struct commander_t commander_t;

commander_t *commander_new(pinetime_t *pt);
void commander_set_output(commander_t *, commander_output_t, void *userdata);
void commander_free(commander_t *);

void commander_run_command(commander_t *, const char *command);
