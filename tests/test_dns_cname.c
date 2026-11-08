#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"

void test_dns_format_cname(void)
{
    printf("Testing CNAME record formatting...\n");

    /*
     * DNS response:
     *
     * Question: www.example.com
     * Answer:   www.example.com CNAME example.net
     */

    const uint8_t packet[] = {
        // DNS header
        0x12, 0x34,             // Transaction ID
        0x81, 0x80,             // Flags: standard response, no error
        0x00, 0x01,             // QDCOUNT: 1
        0x00, 0x01,             // ANCOUNT: 1
        0x00, 0x00,             // NSCOUNT: 0
        0x00, 0x00,             // ARCOUNT: 0

        // Question: www.example.com
        0x03, 'w', 'w', 'w',
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,             // QTYPE: A
        0x00, 0x01,             // QCLASS: IN

        // Answer name: pointer to question name (offset 12)
        0xC0, 0x0C,

        0x00, 0x05,             // TYPE: CNAME
        0x00, 0x01,             // CLASS: IN
        0x00, 0x00, 0x00, 0x3C, // TTL: 60
        0x00, 0x0D,             // RDLENGTH: 13

        // RDATA: example.net
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'n', 'e', 't',
        0x00
    };

    struct dns_question question;
    struct dns_resource_record record;

    size_t offset = DNS_HEADER_SIZE;

    assert(dns_parse_question(
        packet,
        sizeof(packet),
        &offset,
        &question
    ));

    assert(dns_parse_resource_record(
        packet,
        sizeof(packet),
        &offset,
        &record
    ));

    assert(record.type == 5);
    assert(record.rdlength == 13);

    char buffer[DNS_NAME_MAX_LENGTH];

    assert(dns_format_cname(
        packet,
        sizeof(packet),
        &record,
        buffer,
        sizeof(buffer)
    ));

    assert(strcmp(buffer, "example.net") == 0);

    printf("CNAME formatting passed!\n");
}

void test_dns_format_compressed_cname(void)
{
    printf("Testing compressed CNAME record formatting...\n");

    const uint8_t packet[] = {
        // DNS header
        0x12, 0x34,
        0x81, 0x80,
        0x00, 0x01,             // QDCOUNT: 1
        0x00, 0x01,             // ANCOUNT: 1
        0x00, 0x00,
        0x00, 0x00,

        // Question: www.example.com
        0x03, 'w', 'w', 'w',
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,
        0x00, 0x01,

        // Answer owner: pointer to www.example.com (offset 12)
        0xC0, 0x0C,

        0x00, 0x05,             // TYPE: CNAME
        0x00, 0x01,             // CLASS: IN
        0x00, 0x00, 0x00, 0x3C,
        0x00, 0x02,             // RDLENGTH: 2

        // CNAME target: pointer to example.com (offset 16)
        0xC0, 0x10
    };

    struct dns_question question;
    struct dns_resource_record record;

    size_t offset = DNS_HEADER_SIZE;

    assert(dns_parse_question(
        packet,
        sizeof(packet),
        &offset,
        &question
    ));

    assert(dns_parse_resource_record(
        packet,
        sizeof(packet),
        &offset,
        &record
    ));

    assert(record.type == 5);
    assert(record.rdlength == 2);

    char buffer[DNS_NAME_MAX_LENGTH];

    assert(dns_format_cname(
        packet,
        sizeof(packet),
        &record,
        buffer,
        sizeof(buffer)
    ));

    assert(strcmp(buffer, "example.com") == 0);

    printf("Compressed CNAME formatting passed!\n");
}

void test_dns_cname_wrong_type(void)
{
    printf("Testing CNAME with wrong record type...\n");

    const uint8_t packet[] = {0};
    struct dns_resource_record record = {
        .type = 1,
        .rdlength = 1,
        .rdata_offset = 0
    };

    char buffer[DNS_NAME_MAX_LENGTH];

    assert(!dns_format_cname(
        packet,
        sizeof(packet),
        &record,
        buffer,
        sizeof(buffer)
    ));
}

void test_dns_cname_invalid_rdlength(void)
{
    printf("Testing CNAME with invalid RDLENGTH...\n");

    const uint8_t packet[] = {0x00, 0x00};

    struct dns_resource_record record = {
        .type = 5,
        .rdlength = 10,
        .rdata_offset = 1
    };

    char buffer[DNS_NAME_MAX_LENGTH];

    assert(!dns_format_cname(
        packet,
        sizeof(packet),
        &record,
        buffer,
        sizeof(buffer)
    ));
}

void test_dns_cname_rdlength_mismatch(void)
{
    printf("Testing CNAME with mismatched RDLENGTH...\n");

    const uint8_t packet[] = {
        0x00, 0x00
    };

    struct dns_resource_record record = {
        .type = 5,
        .rdlength = 2,
        .rdata_offset = 0
    };

    char buffer[DNS_NAME_MAX_LENGTH];

    assert(!dns_format_cname(
        packet,
        sizeof(packet),
        &record,
        buffer,
        sizeof(buffer)
    ));
}

void test_dns_cname_invalid_pointer(void)
{
    printf("Testing CNAME with invalid compression pointer...\n");

    const uint8_t packet[] = {
        0xC0, 0x00
    };

    struct dns_resource_record record = {
        .type = 5,
        .rdlength = 2,
        .rdata_offset = 0
    };

    char buffer[DNS_NAME_MAX_LENGTH];

    assert(!dns_format_cname(
        packet,
        sizeof(packet),
        &record,
        buffer,
        sizeof(buffer)
    ));
}
