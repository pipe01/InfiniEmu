DEBUG := 0
PROFILE := 0

DUMPS = $(patsubst dumps/%.bin, dumps/%.h, $(wildcard dumps/*.bin))

IDIR = include
ODIR = obj
LDIR = lib
SDIR = src
TDIR = test

CC = gcc
CFLAGS = -I$(IDIR) -I$(LDIR) -Werror -Wall -Wextra -Wno-unused-parameter -pedantic

ifeq ($(DEBUG), 1)
	CFLAGS += -g -O0

	ifeq ($(PROFILE), 1)
		CFLAGS += -pg
	endif
else
	CFLAGS += -O3
endif

LIBS = -lm -lcapstone

DEPS = $(shell find $(IDIR) -type f -name '*.h')

_OBJ = $(patsubst %.c,%.o,$(shell find $(SDIR) -type f -name '*.c'))
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

TEST_BIN = ./tests.out

$(ODIR)/$(LDIR)/%.o: $(LDIR)/%.c $(DEPS)
	mkdir -p $(shell dirname $@)
	$(CC) -c -o $@ $<

$(ODIR)/%.o: %.c $(DEPS)
	mkdir -p $(shell dirname $@)
	$(CC) -c -o $@ $< $(CFLAGS)

infiniemu: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

dumps/%.h: dumps/%.bin
	xxd -i $< > $@

test: gen-test build-test
	$(TEST_BIN); rm -f $(TEST_BIN)
.PHONY: test

gen-test:
	cd $(TDIR) && python3 generate_tests.py
.PHONY: gen-test

build-test: obj/src/cpu.o obj/src/memory.o $(patsubst %.c,obj/%.o,$(wildcard src/peripherals/*.c)) test/main.o
	$(CC) -o $(TEST_BIN) $^ $(CFLAGS) $(LIBS)
.PHONY: build-test

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ $(TEST_BIN) $(TDIR)/main.o
.PHONY: clean

dumps: $(DUMPS)
.PHONY: dumps
