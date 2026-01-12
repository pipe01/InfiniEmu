#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../../lib/littlefs/lfs.h"

/* ---------------- Configuration ---------------- */

#define BLOCK_SIZE 4096
#define BLOCK_COUNT 844
#define CACHE_SIZE 4096
#define LOOKAHEAD_SIZE 16

#define DEFAULT_OFFSET 0xB4000

static FILE *image;
static uint64_t fs_offset = DEFAULT_OFFSET;

const char *get_lfs_error(int err);

/* ---------------- Block device callbacks ---------------- */

static int block_read(const struct lfs_config *c,
                      lfs_block_t block,
                      lfs_off_t off,
                      void *buffer,
                      lfs_size_t size)
{
    uint64_t addr = fs_offset +
                    (uint64_t)block * c->block_size + off;
    fseek(image, addr, SEEK_SET);
    fread(buffer, 1, size, image);
    return 0;
}

static int block_prog(const struct lfs_config *c,
                      lfs_block_t block,
                      lfs_off_t off,
                      const void *buffer,
                      lfs_size_t size)
{
    uint64_t addr = fs_offset +
                    (uint64_t)block * c->block_size + off;
    fseek(image, addr, SEEK_SET);
    fwrite(buffer, 1, size, image);
    fflush(image);
    return 0;
}

static int block_erase(const struct lfs_config *c,
                       lfs_block_t block)
{
    uint8_t buf[BLOCK_SIZE];
    memset(buf, 0xFF, sizeof(buf));

    uint64_t addr = fs_offset +
                    (uint64_t)block * c->block_size;
    fseek(image, addr, SEEK_SET);
    fwrite(buf, 1, sizeof(buf), image);
    fflush(image);
    return 0;
}

static int block_sync(const struct lfs_config *c)
{
    fflush(image);
    return 0;
}

/* ---------------- Main ---------------- */

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        printf("Usage:\n");
        printf("  %s <image.bin> [--offset bytes] read <path>\n", argv[0]);
        printf("  %s <image.bin> [--offset bytes] write <path>\n", argv[0]);
        printf("  %s <image.bin> [--offset bytes] ls <path>\n", argv[0]);
        printf("  %s <image.bin> [--offset bytes] mkdir <path>\n", argv[0]);
        return 1;
    }

    int argi = 1;
    const char *image_path = argv[argi++];

    if (argi + 1 < argc && strcmp(argv[argi], "--offset") == 0)
    {
        fs_offset = strtoull(argv[argi + 1], NULL, 0);
        argi += 2;
    }

    const char *command = argv[argi++];
    const char *path = argv[argi];

    image = fopen(image_path, "rb+");
    if (!image)
    {
        perror("Failed to open image");
        return 1;
    }

    lfs_t lfs;
    struct lfs_config cfg = {
        .read = block_read,
        .prog = block_prog,
        .erase = block_erase,
        .sync = block_sync,

        .read_size = 16,
        .prog_size = 16,
        .block_size = BLOCK_SIZE,
        .block_count = BLOCK_COUNT,
        .cache_size = CACHE_SIZE,
        .lookahead_size = LOOKAHEAD_SIZE,
        .block_cycles = 500,
    };
    int res;

    if ((res = lfs_mount(&lfs, &cfg)) != 0)
    {
        fprintf(stderr, "Failed to mount: %s\n", get_lfs_error(res));
        fclose(image);
        return 1;
    }

    if (strcmp(command, "read") == 0)
    {
        lfs_file_t file;
        if ((res = lfs_file_open(&lfs, &file, path, LFS_O_RDONLY)) == 0)
        {
            char buf[256];
            int n;
            while ((n = lfs_file_read(&lfs, &file, buf, sizeof(buf))) > 0)
            {
                fwrite(buf, 1, n, stdout);
            }

            if ((res = lfs_file_close(&lfs, &file)) != 0)
            {
                fprintf(stderr, "Failed to close file: %s\n", get_lfs_error(res));
            }
        }
        else
        {
            fprintf(stderr, "Failed to open file: %s\n", get_lfs_error(res));
        }
    }
    else if (strcmp(command, "write") == 0)
    {
        lfs_file_t file;
        if (lfs_file_open(&lfs, &file, path,
                          LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC) == 0)
        {
            char buf[256];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0)
            {
                lfs_file_write(&lfs, &file, buf, n);
            }

            if ((res = lfs_file_close(&lfs, &file)) != 0)
            {
                fprintf(stderr, "Failed to close file: %s\n", get_lfs_error(res));
            }
            else
            {
                printf("Write successful\n");
            }
        }
        else
        {
            fprintf(stderr, "Failed to open file: %s\n", get_lfs_error(res));
        }
    }
    else if (strcmp(command, "ls") == 0)
    {
        lfs_dir_t dir;
        struct lfs_info info;

        if ((res = lfs_dir_open(&lfs, &dir, path)) == 0)
        {
            while ((res = lfs_dir_read(&lfs, &dir, &info)) > 0)
            {
                printf("%s\n", info.name);
            }

            if (res < 0)
            {
                fprintf(stderr, "Failed to read directory: %s\n", get_lfs_error(res));
            }

            if ((res = lfs_dir_close(&lfs, &dir)) != 0)
            {
                fprintf(stderr, "Failed to close directory: %s\n", get_lfs_error(res));
            }
        }
        else
        {
            fprintf(stderr, "Failed to open directory: %s\n", get_lfs_error(res));
        }
    }
    else if (strcmp(command, "mkdir") == 0)
    {
        if ((res = lfs_mkdir(&lfs, path)) != 0)
        {
            fprintf(stderr, "Failed to create directory: %s\n", get_lfs_error(res));
        }
        else
        {
            printf("Directory created successfully\n");
        }
    }
    else
    {
        fprintf(stderr, "Unknown command: %s\n", command);
    }

    lfs_unmount(&lfs);
    fclose(image);
    return 0;
}

const char *get_lfs_error(int err)
{
    switch (err)
    {
    case LFS_ERR_IO:
        return "Error during device operation";
    case LFS_ERR_CORRUPT:
        return "Corrupted";
    case LFS_ERR_NOENT:
        return "No directory entry";
    case LFS_ERR_EXIST:
        return "Entry already exists";
    case LFS_ERR_NOTDIR:
        return "Entry is not a dir";
    case LFS_ERR_ISDIR:
        return "Entry is a dir";
    case LFS_ERR_NOTEMPTY:
        return "Dir is not empty";
    case LFS_ERR_BADF:
        return "Bad file number";
    case LFS_ERR_FBIG:
        return "File too large";
    case LFS_ERR_INVAL:
        return "Invalid parameter";
    case LFS_ERR_NOSPC:
        return "No space left on device";
    case LFS_ERR_NOMEM:
        return "No more memory available";
    case LFS_ERR_NOATTR:
        return "No data/attr available";
    case LFS_ERR_NAMETOOLONG:
        return "File name too long";
    }

    return "Unknown error";
}
