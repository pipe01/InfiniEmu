DUMPS = $(patsubst dumps/%.bin, dumps/%.h, $(wildcard dumps/*.bin))

IDIR = include
ODIR = obj
LDIR = lib

CC = gcc
CFLAGS = -I$(IDIR) -I$(LDIR) -g -Werror -Wall -Wextra -Wno-unused-parameter -pedantic

LIBS = -lm -lcapstone

DEPS = $(shell find $(IDIR) -type f -name '*.h')

_OBJ = src/infiniemu.o src/gdb.o src/cpu.o src/nrf52832.o src/memory.o src/peripherals/nvic.o lib/libgdbstub/gdb-stub.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/$(LDIR)/%.o: $(LDIR)/%.c $(DEPS)
	mkdir -p $(shell dirname $@)
	$(CC) -c -o $@ $<

$(ODIR)/%.o: %.c $(DEPS)
	mkdir -p $(shell dirname $@)
	$(CC) -c -o $@ $< $(CFLAGS)

infiniemu: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ 

dumps: $(DUMPS)
.PHONY: dumps

dumps/%.h: dumps/%.bin
	xxd -i $< > $@
