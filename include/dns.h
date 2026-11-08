#ifndef QUERYTRAIL_DNS_H
#define QUERYTRAIL_DNS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DNS_HEADER_SIZE 12

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

#endif

