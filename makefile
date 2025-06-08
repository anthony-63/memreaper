SRC = src/

OUT = memreaper

$(OUT): $(SRC)
	odin build $(SRC) -out:$(OUT)

run: $(OUT)
	./$(OUT)