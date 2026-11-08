
#include <assert.h>

#include "dns.h"

void test_dns_header(void)
{
    const uint8_t packet[] = {
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query, recursion desired
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answers: 0
        0x00, 0x00, // Authority: 0
        0x00, 0x00  // Additional: 0
    };

    struct dns_header header;

    // Valid DNS header
    assert(dns_parse_header(
        packet,
        sizeof(packet),
        &header
    ));

    assert(header.id == 0x1234);
    assert(header.flags == 0x0100);
    assert(header.qdcount == 1);
    assert(header.ancount == 0);
    assert(header.nscount == 0);
    assert(header.arcount == 0);

    // Truncated DNS header
    const uint8_t invalid_packet[] = {
        0x12, 0x34, 0x01, 0x00
    };

    assert(!dns_parse_header(
        invalid_packet,
        sizeof(invalid_packet),
        &header
    ));

    // NULL arguments
    assert(!dns_parse_header(packet, sizeof(packet), NULL));
    assert(!dns_parse_header(NULL, sizeof(packet), &header));
}
