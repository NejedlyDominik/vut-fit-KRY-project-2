CC=gcc
CFLAGS=-std=c17 -Wall -Wextra -pedantic -O3 #-lgmp -lgmpxx -fsanitize=address -fsanitize=leak -I /opt/homebrew/include -L /opt/homebrew/lib
SRC=main.c
BIN=kry
PACK=213486.zip

.PHONY: all pack clean

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@

pack: $(PACK)

$(PACK): $(SRC) Makefile README.md 
	zip -r $@ $^

clean:
	rm -f $(BIN) $(PACK)
