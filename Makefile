PROJ_NAME=ettin

SRCS  = $(wildcard src/*.c)
HEADERS = $(wildcard inc/*.h)

OBJS = $(patsubst src/%,build/%,$(SRCS:.c=.o))

CC=gcc

CFLAGS=  -Wall -Iinc -g
LDFLAGS= -g -lpcap -lz -lpthread -liptc -lip4tc -lip6tc


.PHONY: all proj clean ed

all: proj

proj : $(PROJ_NAME).elf


$(PROJ_NAME).elf: $(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

build/%.o: src/%.c
	$(CC) -c $(CFLAGS) $^ -o $@

ed :
	emacs src/*.c inc/*.h Makefile >/dev/null 2>&1 &

clean:
	rm -f $(OBJS) src/*~ inc/*~ *~
