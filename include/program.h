#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct program_t program_t;

program_t *program_new(size_t size);
void program_free(program_t *);

size_t program_size(const program_t *);
void program_write_to(const program_t *, uint8_t *data, size_t size);

void program_load(program_t *, size_t offset, const uint8_t *data, size_t size);
void program_load_binary(program_t *, size_t offset, const uint8_t *data, size_t size);
bool program_load_elf(program_t *, size_t offset, const uint8_t *data, size_t size);

bool program_find_symbol(const program_t *program, const char *name, size_t *address, size_t *size);
