IDIR =../include
CC=gcc
CFLAGS=-I$(IDIR) -g -Werror -Wall -Wextra -Wno-unused-parameter -pedantic

ODIR=obj
LDIR =../lib

LIBS=-lm -lcapstone

DEPS = $(shell find $(IDIR) -type f -name '*.h')

_OBJ = infiniemu.o cpu.o nrf52832.o memory.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

infiniemu: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ 