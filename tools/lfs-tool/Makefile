LFS_PATH = ../../lib/littlefs

lfs-tool: main.c
	$(CC) $(CFLAGS) -I$(LFS_PATH) -o lfs-tool main.c $(LFS_PATH)/lfs.c $(LFS_PATH)/lfs_util.c

install: lfs-tool
	sudo install lfs-tool /usr/local/bin
