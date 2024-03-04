CC=g++
CFLAGS=-std=c++14 -Wall -Wextra -pedantic -O3
SRC=main.cpp
BIN=kry
PACK=213486.zip

.PHONY: pack clean

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(BIN)

pack: $(PACK)

$(PACK): $(SRC) Makefile README.md 
	zip -r $(PACK) $^

clean:
	rm -f $(BIN) $(PACK)
