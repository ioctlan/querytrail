#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "dns.h"

void test_dns_question(void)
{
    const uint8_t packet[] = {
        // DNS header (12 bytes)
        0x00, 0x01, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        // QNAME: www.example.com
        0x03, 'w', 'w', 'w',
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,

        // QTYPE: A (1)
        0x00, 0x01,

        // QCLASS: IN (1)
        0x00, 0x01
    };

    size_t offset = DNS_HEADER_SIZE;
    struct dns_question question;

    assert(dns_parse_question(
        packet,
        sizeof(packet),
        &offset,
        &question
    ));

    assert(strcmp(question.name, "www.example.com") == 0);
    assert(question.qtype == 1);
    assert(question.qclass == 1);

    assert(offset == sizeof(packet));

    // Truncated QNAME
    offset = DNS_HEADER_SIZE;

    assert(!dns_parse_question(
        packet,
        DNS_HEADER_SIZE + 3,
        &offset,
        &question
    ));

    // Truncated QCLASS
    offset = DNS_HEADER_SIZE;

    assert(!dns_parse_question(
        packet,
        sizeof(packet) - 2,
        &offset,
        &question
    ));
}

void test_dns_question_compression(void)
{
    uint8_t packet[] = {
        // DNS header (12 bytes)
        0x00, 0x01, // ID
        0x01, 0x00, // Flags
        0x00, 0x02, // QDCOUNT: 2 questions
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT

        // First question: example.com
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,       // End of name
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN

        // Second question: www.example.com
        0x03, 'w', 'w', 'w',
        0xC0, 0x0C, // Pointer to offset 12
        0x00, 0x01, // QTYPE: A
        0x00, 0x01  // QCLASS: IN
    };

    struct dns_question question;
    size_t offset = DNS_HEADER_SIZE;

    // Parse the first question.
    assert(dns_parse_question(
        packet, sizeof(packet), &offset, &question
    ));

    assert(strcmp(question.name, "example.com") == 0);
    assert(offset == 29);

    // Parse the second question.
    assert(dns_parse_question(
        packet, sizeof(packet), &offset, &question
    ));

    assert(strcmp(question.name, "www.example.com") == 0);
    assert(offset == 39);
}

void test_dns_question_invalid_compression(void)
{
    struct dns_question question;

    // Case 1: Truncated pointer (only one byte).
    uint8_t truncated[] = {
        0x00, 0x01, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xC0
    };

    size_t offset = DNS_HEADER_SIZE;

    assert(!dns_parse_question(
        truncated, sizeof(truncated), &offset, &question
    ));
    assert(offset == DNS_HEADER_SIZE);

    // Case 2: Pointer references itself.
    uint8_t self_reference[] = {
        0x00, 0x01, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xC0, 0x0C
    };

    offset = DNS_HEADER_SIZE;

    assert(!dns_parse_question(
        self_reference, sizeof(self_reference), &offset, &question
    ));
    assert(offset == DNS_HEADER_SIZE);

    // Case 3: Forward pointer.
    uint8_t forward_pointer[] = {
        0x00, 0x01, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xC0, 0x0D, 0x00, 0x01, 0x00, 0x01
    };

    offset = DNS_HEADER_SIZE;

    assert(!dns_parse_question(
        forward_pointer, sizeof(forward_pointer), &offset, &question
    ));
    assert(offset == DNS_HEADER_SIZE);
}

void test_dns_question_pointer_chain(void)
{
    uint8_t packet[] = {
        // DNS header
        0x00, 0x01, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        // Offset 12: example.com
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,

        // Offset 25: pointer to offset 12
        0xC0, 0x0C,

        // Offset 27: pointer to offset 25
        0xC0, 0x19,

        // QTYPE and QCLASS
        0x00, 0x01,
        0x00, 0x01
    };

    struct dns_question question;
    size_t offset = 27;

    assert(dns_parse_question(
        packet, sizeof(packet), &offset, &question
    ));

    assert(strcmp(question.name, "example.com") == 0);
    assert(offset == 33);
}
