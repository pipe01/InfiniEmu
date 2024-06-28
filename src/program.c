#include "program.h"

#include "demangle.h"

#include <assert.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct program_t
{
    size_t size;
    uint8_t *data;

    void *elf;
};

program_t *program_new(size_t size)
{
    program_t *program = malloc(sizeof(program_t));
    program->size = size;
    program->data = malloc(size);
    memset(program->data, 0xFF, size);
    program->elf = NULL;

    return program;
}

void program_free(program_t *program)
{
    if (program->elf)
        free(program->elf);

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

    const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *)data;

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

    program->elf = malloc(size);
    memcpy(program->elf, data, size);

    return true;
}

bool program_find_symbol(const program_t *program, const char *name, size_t *address, size_t *size)
{
    const Elf32_Ehdr *ehdr = program->elf;

    if (ehdr->e_shstrndx >= ehdr->e_shnum)
        return false;

    const Elf32_Shdr *shstr = (const Elf32_Shdr *)(program->elf + ehdr->e_shoff + ehdr->e_shstrndx * ehdr->e_shentsize);
    const char *shstrtab = (const char *)(program->elf + shstr->sh_offset);

    const char *strtab = NULL;

    for (size_t i = 0; i < ehdr->e_shnum; i++)
    {
        const Elf32_Shdr *shdr = (const Elf32_Shdr *)(program->elf + ehdr->e_shoff + i * ehdr->e_shentsize);

        if (shdr->sh_type == SHT_STRTAB && strcmp(".strtab", shstrtab + shdr->sh_name) == 0)
        {
            strtab = (const char *)(program->elf + shdr->sh_offset);
        }
    }

    if (strtab == NULL)
        return false;

    for (size_t i = 0; i < ehdr->e_shnum; i++)
    {
        const Elf32_Shdr *shdr = (const Elf32_Shdr *)(program->elf + ehdr->e_shoff + i * ehdr->e_shentsize);

        if (shdr->sh_type == SHT_SYMTAB)
        {
            size_t num_sym = shdr->sh_size / shdr->sh_entsize;

            for (size_t j = 0; j < num_sym; j++)
            {
                const Elf32_Sym *sym = (const Elf32_Sym *)(program->elf + shdr->sh_offset + j * shdr->sh_entsize);

                if (sym->st_name == 0)
                    continue;

                const char *sym_name = strtab + sym->st_name;

                char *demangled = demangle(sym_name);

                if (strcmp(name, demangled ? demangled : sym_name) == 0)
                {
                    if (address)
                        *address = sym->st_value;

                    if (size)
                        *size = sym->st_size;

                    if (demangled)
                        free(demangled);

                    return true;
                }

                if (demangled)
                    free(demangled);
            }
        }
    }

    return false;
}
