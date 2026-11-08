CC = cc

VERSION = $(shell cat VERSION)

CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -Werror -O2
CFLAGS += -DQUERYTRAIL_VERSION=\"$(VERSION)\"

TARGET = querytrail
SOURCES = src/main.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES) VERSION
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)

clean:
	rm -f $(TARGET)

