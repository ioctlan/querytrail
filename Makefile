CC = cc

VERSION = $(shell cat VERSION)

CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -Werror -O2
CFLAGS += -DQUERYTRAIL_VERSION=\"$(VERSION)\"
CPPFLAGS = -Iinclude

TARGET = querytrail
SOURCES = src/main.c src/dns.c

TEST_TARGET = build/tests/querytrail_tests
TEST_SOURCES = tests/test_main.c tests/test_dns_header.c src/dns.c

.PHONY: all test clean

all: $(TARGET)

$(TARGET): $(SOURCES) VERSION
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) -o $(TARGET)

$(TEST_TARGET): $(TEST_SOURCES)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(TEST_SOURCES) -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -f $(TARGET)
	rm -rf build/