
CC = cc
PKG_CONFIG ?= pkg-config

VERSION = $(shell cat VERSION)

CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -Werror -O2
CFLAGS += -DQUERYTRAIL_VERSION=\"$(VERSION)\"

CPPFLAGS = -Iinclude
PCAP_CFLAGS = $(shell $(PKG_CONFIG) --cflags libpcap)
PCAP_LIBS = $(shell $(PKG_CONFIG) --libs libpcap)

TARGET = querytrail

SOURCES = \
	src/main.c \
	src/capture.c \
	src/packet.c \
	src/dns.c \
	src/presentation.c

TEST_TARGET = build/tests/querytrail_tests

TEST_SOURCES = \
	tests/test_main.c \
	tests/test_dns_header.c \
	tests/test_dns_question.c \
	tests/test_dns_record.c \
	tests/test_dns_cname.c \
	tests/test_dns_message.c \
	tests/test_dns_mx.c \
	src/dns.c

.PHONY: all test clean

all: $(TARGET)

$(TARGET): $(SOURCES) VERSION
	$(CC) $(CPPFLAGS) $(PCAP_CFLAGS) $(CFLAGS) $(SOURCES) $(PCAP_LIBS) -o $@

$(TEST_TARGET): $(TEST_SOURCES)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(TEST_SOURCES) -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -f $(TARGET)
	rm -f *.o
	rm -rf build/
