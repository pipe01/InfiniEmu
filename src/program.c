#include "program.h"

#include <assert.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct program_t
{
    size_t size;
    uint8_t *data;
};

program_t *program_new(size_t size)
{
    program_t *program = malloc(sizeof(program_t));
    program->size = size;
    program->data = malloc(size);
    memset(program->data, 0xFF, size);

    return program;
}

void program_free(program_t *program)
{
    free(program->data);
    free(program);
}

size_t program_size(const program_t *program)
{
    return program->size;
}

void program_write_to(const program_t *program, uint8_t *data, size_t size)
{
    memcpy(data, program->data, size > program->size ? program->size : size);
}

void program_load_binary(program_t *program, size_t offset, const uint8_t *data, size_t size)
{
    assert(offset + size <= program->size);

    memcpy(program->data + offset, data, size);
}

bool program_load_elf(program_t *program, size_t offset, const uint8_t *data, size_t size)
{
    if (size < sizeof(Elf32_Ehdr))
        return false;

    const Elf32_Ehdr *ehdr = (Elf32_Ehdr *)data;

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
        return false;

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS32)
        return false;

    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
        return false;

    for (size_t i = 0; i < ehdr->e_phnum; i++)
    {
        const Elf32_Phdr *phdr = (const Elf32_Phdr *)(data + ehdr->e_phoff + i * ehdr->e_phentsize);

        size_t start = offset + phdr->p_paddr;
        size_t end = start + phdr->p_filesz;

        if (end <= program->size)
            memcpy(program->data + start, data + phdr->p_offset, phdr->p_filesz);
    }

    return true;
}
