DEBUG := 0
OPTIMIZE := 1
PROFILE := 0
WASM := 0

DUMPS = $(patsubst dumps/%.bin, dumps/%.h, $(wildcard dumps/*.bin))

IDIR = ./include
ODIR = obj
LDIR = lib
SDIR = src
TDIR = test

CC = gcc
CFLAGS = -I$(IDIR) -I$(LDIR) -fPIC -Werror -Wall -Wextra -Wno-unused-parameter

LIBS = $(LDFLAGS) -lm

WASM_FUNCS = malloc pinetime_new pinetime_step pinetime_loop
WASM_FUNCS += pinetime_get_st7789 st7789_read_screen st7789_is_sleeping st7789_get_write_count
WASM_FUNCS += pinetime_get_cst816s cst816s_do_touch cst816s_release_touch
WASM_FUNCS += pinetime_get_nrf52832 nrf52832_get_pins pins_set pins_clear

ifeq ($(WASM), 1)
	CFLAGS += -I/usr/include/capstone
	CC = emcc
else
	CFLAGS += -pedantic
	LIBS += -lcapstone
endif

ifeq ($(DEBUG), 1)
	CFLAGS += -g
endif

ifeq ($(OPTIMIZE), 1)
	CFLAGS += -O3
else
	CFLAGS += -O0
endif

ifeq ($(PROFILE), 1)
	CFLAGS += -pg
endif

DEPS = $(shell find $(IDIR) -type f -name '*.h')

_OBJ = $(patsubst %.c,%.o,$(shell find $(SDIR) -type f -name '*.c' ! -name "infiniemu.c"))
_OBJ += $(LDIR)/tiny-AES-c/aes.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

TEST_BIN = ./tests.out

comma := ,
empty :=
space := $(empty) $(empty)
_WASM_FUNCS := $(subst $(space),$(comma),$(patsubst %,_%,$(WASM_FUNCS)))

$(ODIR)/$(LDIR)/%.o: $(LDIR)/%.c $(DEPS)
	mkdir -p $(shell dirname $@)
	$(CC) -c -o $@ $<

$(ODIR)/%.o: %.c $(DEPS)
	mkdir -p $(shell dirname $@)
	$(CC) -c -o $@ $< $(CFLAGS)

infiniemu: $(OBJ) obj/src/infiniemu.o
	$(CC) -o $@ $^ -static $(CFLAGS) $(LIBS)

infiniemu.wasm: $(OBJ)
	$(CC) -o infiniemu.js -sTOTAL_STACK=64MB -sALLOW_MEMORY_GROWTH -sEXPORTED_RUNTIME_METHODS=ccall,cwrap -sEXPORTED_FUNCTIONS=$(_WASM_FUNCS) capstone-5.0.1/libcapstone.a $^

libinfiniemu.o: $(OBJ)
	ld -relocatable -static $^ -o $@

libinfiniemu.so: $(OBJ)
	$(CC) -o $@ $^ -shared $(CFLAGS) $(LIBS)

dumps/%.h: dumps/%.bin
	xxd -i $< > $@

test: gen-test build-test
	$(TEST_BIN); rm -f $(TEST_BIN)
.PHONY: test

gen-test:
	cd $(TDIR) && python3 generate_tests.py
.PHONY: gen-test

build-test: obj/src/cpu.o obj/src/memory.o obj/src/runlog.o obj/src/fault.o $(patsubst %.c,obj/%.o,$(wildcard src/peripherals/*.c)) test/main.o
	$(CC) -o $(TEST_BIN) $^ $(CFLAGS) $(LIBS)
.PHONY: build-test

clean:
	rm -rf $(ODIR) *~ core $(INCDIR)/*~ $(TEST_BIN) $(TDIR)/main.o
.PHONY: clean

dumps: $(DUMPS)
.PHONY: dumps

profile: infiniemu
	valgrind --tool=cachegrind --cachegrind-out-file=cachegrind.out ./infiniemu -f infinitime.bin
	cg_annotate cachegrind.out > cachegrind.out.txt
	rm cachegrind.out
.PHONY: profile
