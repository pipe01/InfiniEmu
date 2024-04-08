DUMPS = $(patsubst dumps/%.bin, dumps/%.h, $(wildcard dumps/*.bin))

IDIR = include
ODIR = obj
LDIR = lib
SDIR = src
TDIR = test

CC = gcc
CFLAGS = -I$(IDIR) -I$(LDIR) -g -Werror -Wall -Wextra -Wno-unused-parameter -pedantic

LIBS = -lm -lcapstone

DEPS = $(shell find $(IDIR) -type f -name '*.h')

_OBJ = $(patsubst %.c,%.o,$(shell find $(SDIR) -type f -name '*.c'))
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

TEST_BIN = /tmp/infiniemu-test

$(ODIR)/$(LDIR)/%.o: $(LDIR)/%.c $(DEPS)
	mkdir -p $(shell dirname $@)
	$(CC) -c -o $@ $<

$(ODIR)/%.o: %.c $(DEPS)
	mkdir -p $(shell dirname $@)
	$(CC) -c -o $@ $< $(CFLAGS)

infiniemu: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean test gen-test

test: obj/src/cpu.o obj/src/memory.o test/main.o
	$(CC) -o $(TEST_BIN) $^ $(CFLAGS) $(LIBS)
	$(TEST_BIN); rm -f $(TEST_BIN)

gen-test:
	cd $(TDIR) && python generate_tests.py

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ 

dumps: $(DUMPS)
.PHONY: dumps

dumps/%.h: dumps/%.bin
	xxd -i $< > $@
