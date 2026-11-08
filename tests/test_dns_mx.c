
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"

void test_dns_format_mx(void)
{
    printf("Testing MX record formatting...\n");

    /*
     * DNS response:
     *
     * Question: example.com
     * Answer:   example.com MX 10 mail.example.com
     */

    const uint8_t packet[] = {
        // DNS header
        0x12, 0x34,
        0x81, 0x80,
        0x00, 0x01,             // QDCOUNT: 1
        0x00, 0x01,             // ANCOUNT: 1
        0x00, 0x00,
        0x00, 0x00,

        // Question: example.com
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x0F,             // QTYPE: MX
        0x00, 0x01,             // QCLASS: IN

        // Answer name: pointer to question (offset 12)
        0xC0, 0x0C,

        0x00, 0x0F,             // TYPE: MX
        0x00, 0x01,             // CLASS: IN
        0x00, 0x00, 0x00, 0x3C, // TTL: 60
        0x00, 0x14,             // RDLENGTH: 20

        // RDATA
        0x00, 0x0A,             // Preference: 10

        // Exchange: mail.example.com
        0x04, 'm', 'a', 'i', 'l',
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
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

    assert(record.type == 15);
    assert(record.rdlength == 20);

    uint16_t preference;
    char exchange[DNS_NAME_MAX_LENGTH];

    assert(dns_format_mx(
        packet,
        sizeof(packet),
        &record,
        &preference,
        exchange,
        sizeof(exchange)
    ));

    assert(preference == 10);
    assert(strcmp(exchange, "mail.example.com") == 0);

    printf("MX formatting passed!\n");
}
