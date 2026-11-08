#ifndef QUERYTRAIL_DNS_H
#define QUERYTRAIL_DNS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DNS_HEADER_SIZE 12
#define DNS_NAME_MAX_LENGTH 256

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

bool dns_parse_header(
    const uint8_t *packet,
    size_t packet_len,
    struct dns_header *header
);

struct dns_question {
    char name[DNS_NAME_MAX_LENGTH];
    uint16_t qtype;
    uint16_t qclass;
};

bool dns_parse_question(
    const uint8_t *packet,
    size_t packet_len,
    size_t *offset,
    struct dns_question *question
);

#endif

