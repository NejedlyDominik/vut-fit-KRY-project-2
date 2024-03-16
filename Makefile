CC=gcc
CFLAGS=-std=c17 -Wall -Wextra -Werror -pedantic -O3 -fsanitize=address -fsanitize=leak
SRC_FILES=main.c args.c input.c sha256.c
HEADER_FILES=args.h input.h sha256.h
OBJECT_FILES=main.o args.o input.o sha256.o
BIN=kry
PACK=213486.zip

.PHONY: all pack clean clean-pack

all: $(BIN)

$(BIN): $(HEADER_FILES) $(OBJECT_FILES)
	$(CC) $(CFLAGS) $(OBJECT_FILES) -o $@

$(OBJECT_FILES): %.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

pack: $(PACK)

$(PACK): $(SRC_FILES) $(HEADER_FILES) Makefile README.md 
	zip -r $@ $^

clean:
	rm -f $(OBJECT_FILES) $(BIN)

clean-pack:
	rm -f $(PACK)
