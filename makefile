OUT = memreaper

SRC = $(shell find src -type f -iname '*.ha')

$(OUT): $(SRC)
	hare build -o $(OUT) src
