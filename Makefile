DUMPS = $(patsubst dumps/%.bin, dumps/%.h, $(wildcard dumps/*.bin))

dumps: $(DUMPS)
.PHONY: dumps

dumps/%.h: dumps/%.bin
	xxd -i $< > $@
