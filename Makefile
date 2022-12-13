CC ?= gcc
CFLAGS += -std=gnu99 -Wno-logical-op-parentheses -O2
CFLAGS_BSD = -Wno-address-of-packed-member -Wno-switch
CFLAGS_MAC = -mmacosx-version-min=10.8
LIBS = 
LIBS_WIN = -lws2_32
SRC_FILES = ipfilter.c qsort.c

all: ipfilter

ipfilter: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o ipfilter $(SRC_FILES) $(LDFLAGS) $(LIBS)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) $(CFLAGS_MAC) -o ipfilter $(SRC_FILES) $(LDFLAGS) $(LIBS)
	strip ipfilter

win: $(SRC_FILES)
	$(CC) $(CFLAGS) -o ipfilter $(SRC_FILES) $(LDFLAGS) $(LIBS_WIN)

clean:
	rm -f ipfilter *.o
