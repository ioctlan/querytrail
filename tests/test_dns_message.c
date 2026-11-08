#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"

void test_dns_parse_message(void)
{
    printf("Testing complete DNS message parsing...\n");

    const uint8_t packet[] = {
        // DNS header
        0x12, 0x34,             // Transaction ID
        0x81, 0x80,             // Flags
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

        // Answer owner: pointer to question name
        0xC0, 0x0C,

        0x00, 0x01,             // TYPE: A
        0x00, 0x01,             // CLASS: IN
        0x00, 0x00, 0x00, 0x3C, // TTL: 60
        0x00, 0x04,             // RDLENGTH: 4

        // RDATA: 93.184.216.34
        0x5D, 0xB8, 0xD8, 0x22
    };

    struct dns_message message = {0};

    assert(dns_parse_message(
        packet,
        sizeof(packet),
        &message
    ));

    // Verify DNS header.
    assert(message.header.id == 0x1234);
    assert(message.header.qdcount == 1);
    assert(message.header.ancount == 1);

    // Verify question.
    assert(strcmp(
        message.questions[0].name,
        "www.example.com"
    ) == 0);

    assert(message.questions[0].qtype == 1);
    assert(message.questions[0].qclass == 1);

    // Verify answer.
    assert(strcmp(
        message.answers[0].name,
        "www.example.com"
    ) == 0);

    assert(message.answers[0].type == 1);
    assert(message.answers[0].ttl == 60);

    // Verify original packet reference.
    assert(message.packet == packet);
    assert(message.packet_len == sizeof(packet));

    // Empty sections should have no allocated arrays.
    assert(message.authorities == NULL);
    assert(message.additionals == NULL);

    // Verify address decoding still works.
    char address[INET_ADDRSTRLEN];

    assert(dns_format_address(
        &message.answers[0],
        address,
        sizeof(address)
    ));

    assert(strcmp(address, "93.184.216.34") == 0);

    dns_free_message(&message);

    printf("Complete DNS message parsing passed!\n");
}

void test_dns_message_multiple_questions(void)
{
    printf("Testing DNS message with multiple questions...\n");

    const uint8_t packet[] = {
        // Header
        0x12, 0x34, 0x01, 0x00,
        0x00, 0x02,             // QDCOUNT: 2
        0x00, 0x00,             // ANCOUNT: 0
        0x00, 0x00,             // NSCOUNT: 0
        0x00, 0x00,             // ARCOUNT: 0

        // Question 1: example.com
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,

        // Question 2: google.com
        0x06, 'g', 'o', 'o', 'g', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };

    struct dns_message message = {0};

    assert(dns_parse_message(packet, sizeof(packet), &message));

    assert(message.header.qdcount == 2);

    assert(strcmp(message.questions[0].name, "example.com") == 0);
    assert(strcmp(message.questions[1].name, "google.com") == 0);

    dns_free_message(&message);
}

void test_dns_message_multiple_answers(void)
{
    printf("Testing DNS message with multiple answers...\n");

    const uint8_t packet[] = {
        // Header
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x01,             // QDCOUNT: 1
        0x00, 0x02,             // ANCOUNT: 2
        0x00, 0x00,
        0x00, 0x00,

        // Question: example.com
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,

        // Answer 1: example.com -> 93.184.216.34
        0xC0, 0x0C,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x3C,
        0x00, 0x04,
        0x5D, 0xB8, 0xD8, 0x22,

        // Answer 2: example.com -> 93.184.216.35
        0xC0, 0x0C,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x3C,
        0x00, 0x04,
        0x5D, 0xB8, 0xD8, 0x23
    };

    struct dns_message message = {0};

    assert(dns_parse_message(packet, sizeof(packet), &message));

    assert(message.header.ancount == 2);

    assert(strcmp(message.answers[0].name, "example.com") == 0);
    assert(strcmp(message.answers[1].name, "example.com") == 0);

    char address[INET_ADDRSTRLEN];

    assert(dns_format_address(&message.answers[0], address, sizeof(address)));
    assert(strcmp(address, "93.184.216.34") == 0);

    assert(dns_format_address(&message.answers[1], address, sizeof(address)));
    assert(strcmp(address, "93.184.216.35") == 0);

    dns_free_message(&message);
}

void test_dns_message_malformed_question(void)
{
    printf("Testing malformed DNS message...\n");

    const uint8_t packet[] = {
        // Header
        0x12, 0x34, 0x01, 0x00,
        0x00, 0x02,             // QDCOUNT: 2
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,

        // Only one question is present.
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };

    struct dns_message message = {0};

    assert(!dns_parse_message(packet, sizeof(packet), &message));

    // Failed parsing must not leave allocations behind.
    assert(message.questions == NULL);
    assert(message.answers == NULL);
    assert(message.authorities == NULL);
    assert(message.additionals == NULL);
}

void test_dns_message_trailing_bytes(void)
{
    printf("Testing DNS message with trailing bytes...\n");

    const uint8_t packet[] = {
        // Header
        0x12, 0x34, 0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,

        // Question: example.com
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,

        // Unexpected trailing byte
        0xFF
    };

    struct dns_message message = {0};

    assert(!dns_parse_message(packet, sizeof(packet), &message));
}

void test_dns_free_message(void)
{
    printf("Testing DNS message cleanup...\n");

    const uint8_t packet[] = {
        0x12, 0x34, 0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,

        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };

    struct dns_message message = {0};

    assert(dns_parse_message(packet, sizeof(packet), &message));

    assert(message.questions != NULL);

    dns_free_message(&message);

    assert(message.questions == NULL);
    assert(message.answers == NULL);
    assert(message.authorities == NULL);
    assert(message.additionals == NULL);

    assert(message.packet == NULL);
    assert(message.packet_len == 0);
    assert(message.header.qdcount == 0);

    // Cleanup should also be safe to call twice.
    dns_free_message(&message);
}






