#include "commander.h"
#include "pinetime.h"
#include "components/spi/st7789.h"
#include "littlefs/lfs.h"

#include <emscripten.h>

bool pinetime_loop(pinetime_t *pt, int cycles)
{
    st7789_t *lcd = pinetime_get_st7789(pt);
    size_t initial_write_count = st7789_get_write_count(lcd);

    while (cycles > 0)
    {
        cycles -= pinetime_step(pt);
    }

    return st7789_get_write_count(lcd) != initial_write_count;
}

void st7789_read_screen_rgba(st7789_t *st, uint8_t *screen_buffer, uint8_t *rgba_buffer, size_t width, size_t height)
{
    st7789_read_screen(st, screen_buffer, width, height);

    size_t pixel_idx = 0;

    for (size_t y = 0; y < height; y++)
    {
        for (size_t x = 0; x < width; x++)
        {
            uint16_t pixel16 = screen_buffer[pixel_idx * BYTES_PER_PIXEL + 1] | (screen_buffer[pixel_idx * BYTES_PER_PIXEL] << 8);

            uint16_t r = (pixel16 >> 11) & 0x1f;
            uint16_t g = (pixel16 >> 5) & 0x3f;
            uint16_t b = pixel16 & 0x1f;

            rgba_buffer[pixel_idx * 4] = (r * 527 + 23) >> 6;
            rgba_buffer[pixel_idx * 4 + 1] = (g * 259 + 33) >> 6;
            rgba_buffer[pixel_idx * 4 + 2] = (b * 527 + 23) >> 6;
            rgba_buffer[pixel_idx * 4 + 3] = 0xFF; // Alpha is always 0xFF

            pixel_idx++;
        }
    }
}

void commander_output(const char *msg, void *userdata)
{
    EM_ASM({ commander_output($0); }, msg);
}

void commander_set_wasm_output(commander_t *cmd)
{
    commander_set_output(cmd, commander_output, NULL);
}

int lfs_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer, lfs_size_t size)
{
    memcpy(buffer, c->context + block * c->block_size + off, size);
    return 0;
}

int lfs_prog(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, const void *buffer, lfs_size_t size)
{
    memcpy(c->context + block * c->block_size + off, buffer, size);
    return 0;
}

int lfs_erase(const struct lfs_config *c, lfs_block_t block)
{
    memset(c->context + block * c->block_size, 0xFF, c->block_size);
    return 0;
}

int lfs_sync(const struct lfs_config *c)
{
    return 0;
}

const struct lfs_config lfs_cfg = {
    .read_size = 16,
    .prog_size = 8,
    .block_size = 4096,
    .block_count = 844,
    .block_cycles = 1000,
    .cache_size = 16,
    .lookahead_size = 16,
    .read = lfs_read,
    .prog = lfs_prog,
    .erase = lfs_erase,
    .sync = lfs_sync,
};

lfs_t *lfs_init(uint8_t *data, size_t data_size)
{
    lfs_t *lfs = malloc(sizeof(lfs_t));

    struct lfs_config *cfg = malloc(sizeof(struct lfs_config));
    *cfg = lfs_cfg;
    cfg->context = data;

    lfs->cfg = cfg;

    int err = lfs_mount(lfs, cfg);

    if (err)
    {
        printf("Mounting failed (%d), formatting...\n", err);

        lfs_format(lfs, cfg);
        err = lfs_mount(lfs, cfg);
        if (err)
        {
            printf("Formatting failed (%d)\n", err);

            free(lfs);
            free(cfg);
            return NULL;
        }
    }

    return lfs;
}

void lfs_free_wasm(lfs_t *lfs)
{
    free((void *)lfs->cfg);
    free(lfs);
}

lfs_dir_t *lfs_open_dir(lfs_t *lfs, const char *path)
{
    lfs_dir_t *dir = malloc(sizeof(lfs_dir_t));
    if (lfs_dir_open(lfs, dir, path) < 0)
    {
        free(dir);
        return NULL;
    }

    return dir;
}

struct lfs_info *lfs_info_malloc()
{
    return malloc(sizeof(struct lfs_info));
}

uint8_t lfs_info_type(const struct lfs_info *info)
{
    return info->type;
}

lfs_size_t lfs_info_size(const struct lfs_info *info)
{
    return info->size;
}

const char *lfs_info_name(const struct lfs_info *info)
{
    return info->name;
}

lfs_file_t *lfs_open_file(lfs_t *lfs, const char *path, int flags)
{
    lfs_file_t *file = malloc(sizeof(lfs_file_t));
    if (lfs_file_open(lfs, file, path, flags) < 0)
    {
        free(file);
        return NULL;
    }

    return file;
}

bool program_write_variable(program_t *program, cpu_t *cpu, const char *name, uint32_t lower, uint32_t upper)
{
    size_t address, size;

    if (!program_find_symbol(program, name, &address, &size))
        return false;

    memory_map_t *mem = cpu_mem(cpu);

    switch (size)
    {
    case 1:
        memory_map_write(mem, address, lower, SIZE_BYTE);
        break;

    case 2:
        memory_map_write(mem, address, lower, SIZE_HALFWORD);
        break;

    case 4:
        memory_map_write(mem, address, lower, SIZE_WORD);
        break;

    case 8:
        memory_map_write(mem, address, lower, SIZE_WORD);
        memory_map_write(mem, address + 4, upper, SIZE_WORD);
        break;
    }

    return true;
}
