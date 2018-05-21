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

listmac.txt:
	curl 'https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf'|perl -ae 'chomp;s/&Amp;/&/;s/^#.*//;s/((?:[0-9A-F]{2}:){2}[0-9A-F]{2})\t([\S]+).*/\1:00:00:00\/24;\2/;s/((?:[0-9A-F]{2}:){5}[0-9A-F]{2}\/[0-9]+)\s+(\S+).*/\1;\2/;print $$_."\n" if(length($$_)>0)' > listmac.txt

$(PROJ_NAME).elf: $(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@
	cp $(PROJ_NAME).elf $(PROJ_NAME).elf.stripped
	strip $(PROJ_NAME).elf.stripped

build/%.o: src/%.c
	$(CC) -c $(CFLAGS) $^ -o $@

test/test.o : test/main.c
	$(CC) -c $(CFLAGS) $^ -o $@

test.elf: test/test.o $(filter-out build/main.o, $(OBJS))
	$(CC) $^ $(LDFLAGS) -o $@


ed :
	emacs src/*.c inc/*.h Makefile >/dev/null 2>&1 &

clean:
	rm -f $(OBJS) src/*~ inc/*~ *~
