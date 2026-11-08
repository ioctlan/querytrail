
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "dns.h"

void test_dns_resource_record(void)
{
    uint8_t packet[] = {
        // DNS header
        0x00, 0x01, 0x81, 0x80,
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x01, // ANCOUNT: 1
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0

        // Question: example.com
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN

        // Answer: example.com
        0xC0, 0x0C, // NAME: pointer to offset 12
        0x00, 0x01, // TYPE: A
        0x00, 0x01, // CLASS: IN
        0x00, 0x00, 0x00, 0x3C, // TTL: 60
        0x00, 0x04, // RDLENGTH: 4
        0x5D, 0xB8, 0xD8, 0x22 // RDATA: 93.184.216.34
    };

    struct dns_question question;
    struct dns_resource_record record;

    size_t offset = DNS_HEADER_SIZE;

    // Parse the question first.
    assert(dns_parse_question(
        packet, sizeof(packet), &offset, &question
    ));

    assert(strcmp(question.name, "example.com") == 0);
    assert(offset == 29);

    // Parse the answer.
    assert(dns_parse_resource_record(
        packet, sizeof(packet), &offset, &record
    ));

    assert(strcmp(record.name, "example.com") == 0);
    assert(record.type == 1);
    assert(record.class == 1);
    assert(record.ttl == 60);
    assert(record.rdlength == 4);

    const uint8_t expected_ip[] = {0x5D, 0xB8, 0xD8, 0x22};

    assert(memcmp(record.rdata, expected_ip, sizeof(expected_ip)) == 0);
    assert(offset == 45);
}

void test_dns_resource_record_invalid(void)
{
    struct dns_resource_record record;

    // Case 1: Truncated resource-record metadata.
    uint8_t truncated[] = {
        // Root domain name
        0x00,

        // TYPE and CLASS, but incomplete TTL
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x00
    };

    size_t offset = 0;

    assert(!dns_parse_resource_record(
        truncated, sizeof(truncated), &offset, &record
    ));

    assert(offset == 0);

    // Case 2: RDLENGTH claims 4 bytes, but only 2 exist.
    uint8_t invalid_rdlength[] = {
        // Root domain name
        0x00,

        // TYPE: A
        0x00, 0x01,

        // CLASS: IN
        0x00, 0x01,

        // TTL: 60
        0x00, 0x00, 0x00, 0x3C,

        // RDLENGTH: 4
        0x00, 0x04,

        // Only 2 bytes of RDATA
        0x5D, 0xB8
    };

    offset = 0;

    assert(!dns_parse_resource_record(
        invalid_rdlength,
        sizeof(invalid_rdlength),
        &offset,
        &record
    ));

    assert(offset == 0);
}
