#include <stdio.h>

#include "presentation.h"

#define DNS_FLAG_QR 0x8000

#define DNS_TYPE_A 1
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_AAAA 28

static const char *dns_type_name(uint16_t type)
{
    switch (type) {
        case 1:   return "A";
        case 2:   return "NS";
        case 5:   return "CNAME";
        case 6:   return "SOA";
        case 12:  return "PTR";
        case 15:  return "MX";
        case 16:  return "TXT";
        case 28:  return "AAAA";
        case 33:  return "SRV";
        case 41:  return "OPT";
        case 43:  return "DS";
        case 46:  return "RRSIG";
        case 48:  return "DNSKEY";
        case 64:  return "SVCB";
        case 65:  return "HTTPS";
        case 255: return "ANY";
        default:  return "UNKNOWN";
    }
}

static const char *dns_response_code_name(uint16_t code)
{
    switch (code) {
        case 0:  return "NOERROR";
        case 1:  return "FORMERR";
        case 2:  return "SERVFAIL";
        case 3:  return "NXDOMAIN";
        case 4:  return "NOTIMP";
        case 5:  return "REFUSED";
        case 6:  return "YXDOMAIN";
        case 7:  return "YXRRSET";
        case 8:  return "NXRRSET";
        case 9:  return "NOTAUTH";
        case 10: return "NOTZONE";
        default: return "UNKNOWN";
    }
}


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

    if (is_response) {
        uint16_t response_code = message->header.flags & 0x000F;

        printf("Status: %s (%u)\n",
            dns_response_code_name(response_code),
            response_code);
    }

    printf("Transaction ID: 0x%04x\n", message->header.id);

    printf("Source: %s:%u\n", src_ip, src_port);
    printf("Destination: %s:%u\n", dst_ip, dst_port);

    for (size_t i = 0; i < message->header.qdcount; i++) {
        printf("Question: %s (%s)\n",
            message->questions[i].name,
            dns_type_name(message->questions[i].qtype));
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
            printf("[record type %s]\n", dns_type_name(record->type));
        }
    }

    printf("============================\n\n");
}
