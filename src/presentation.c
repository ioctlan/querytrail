#include <stdio.h>

#include "presentation.h"

#define DNS_FLAG_QR 0x8000

#define DNS_TYPE_A 1
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_AAAA 28

void presentation_dns_message(
    const struct dns_message *message,
    const char *src_ip,
    uint16_t src_port,
    const char *dst_ip,
    uint16_t dst_port
)
{
    if (message == NULL) {
        return;
    }

    bool is_response = (message->header.flags & DNS_FLAG_QR) != 0;

    printf("\n========== DNS %s ==========\n",
           is_response ? "RESPONSE" : "QUERY");

    printf("Transaction ID: 0x%04x\n", message->header.id);

    printf("Source: %s:%u\n", src_ip, src_port);
    printf("Destination: %s:%u\n", dst_ip, dst_port);

    for (size_t i = 0; i < message->header.qdcount; i++) {
        printf("Question: %s (type %u)\n",
               message->questions[i].name,
               message->questions[i].qtype);
    }

    for (size_t i = 0; i < message->header.ancount; i++) {
        const struct dns_resource_record *record = &message->answers[i];

        char formatted[DNS_NAME_MAX_LENGTH];

        printf("Answer: %s ", record->name);

        if (record->type == DNS_TYPE_A ||
            record->type == DNS_TYPE_AAAA) {

            if (dns_format_address(
                    record,
                    formatted,
                    sizeof(formatted))) {
                printf("%s\n", formatted);
            } else {
                printf("[invalid address record]\n");
            }

        } else if (record->type == DNS_TYPE_CNAME) {

            if (dns_format_cname(
                    message->packet,
                    message->packet_len,
                    record,
                    formatted,
                    sizeof(formatted))) {
                printf("CNAME %s\n", formatted);
            } else {
                printf("[invalid CNAME record]\n");
            }

        } else {
            printf("[record type %u]\n", record->type);
        }
    }

    printf("============================\n\n");
}
