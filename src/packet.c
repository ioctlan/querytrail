
#include <stdio.h>
#include <stdint.h>
#include <pcap/pcap.h>

#include "dns.h"
#include "packet.h"

#define PACKET_ETHERNET_HEADER_SIZE 14

#define PACKET_ETHERTYPE_IPV4 0x0800
#define PACKET_ETHERTYPE_IPV6 0x86DD
#define PACKET_ETHERTYPE_VLAN 0x8100
#define PACKET_IPV4_MIN_HEADER_SIZE 20
#define PACKET_IPV4_PROTOCOL_UDP 17
#define PACKET_UDP_HEADER_SIZE 8
#define PACKET_DNS_PORT 53
#define PACKET_IPV4_FRAGMENT_MASK 0x3FFF
#define PACKET_DNS_TYPE_A 1
#define PACKET_DNS_TYPE_CNAME 5
#define PACKET_DNS_TYPE_AAAA 28


static uint16_t read_be16(const uint8_t *data)
{
    return ((uint16_t)data[0] << 8) |
           (uint16_t)data[1];
}

static void process_dns(
    const uint8_t *payload,
    size_t payload_len
)
{
    struct dns_message message = {0};

    if (!dns_parse_message(payload, payload_len, &message)) {
        fprintf(stderr, "Failed to parse DNS message\n");
        return;
    }

    bool is_response = (message.header.flags & 0x8000) != 0;

    printf("\n========== DNS %s ==========\n",
           is_response ? "RESPONSE" : "QUERY");

    printf("Transaction ID: 0x%04x\n", message.header.id);

    for (size_t i = 0; i < message.header.qdcount; i++) {
        printf("Question: %s (type %u)\n",
               message.questions[i].name,
               message.questions[i].qtype);
    }

    for (size_t i = 0; i < message.header.ancount; i++) {
        struct dns_resource_record *record = &message.answers[i];

        printf("Answer: %s ", record->name);

        char formatted[DNS_NAME_MAX_LENGTH];

        if (record->type == PACKET_DNS_TYPE_A ||
            record->type == PACKET_DNS_TYPE_AAAA) {

            if (dns_format_address(
                    record,
                    formatted,
                    sizeof(formatted))) {
                printf("%s\n", formatted);
            } else {
                printf("[invalid address record]\n");
            }

        } else if (record->type == PACKET_DNS_TYPE_CNAME) {

            if (dns_format_cname(
                    payload,
                    payload_len,
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

    dns_free_message(&message);
}

static void process_udp(
    const uint8_t *udp,
    size_t captured_len,
    const char *src_ip,
    const char *dst_ip
)
{
    if (captured_len < PACKET_UDP_HEADER_SIZE) {
        return;
    }

    uint16_t src_port = read_be16(udp);
    uint16_t dst_port = read_be16(udp + 2);
    uint16_t udp_len = read_be16(udp + 4);

    if (udp_len < PACKET_UDP_HEADER_SIZE || udp_len > captured_len) {
        return;
    }

    if (src_port != PACKET_DNS_PORT &&
        dst_port != PACKET_DNS_PORT) {
        return;
    }

    const uint8_t *dns_payload = udp + PACKET_UDP_HEADER_SIZE;
    size_t dns_payload_len = udp_len - PACKET_UDP_HEADER_SIZE;

    printf("%s:%u -> %s:%u\n",
           src_ip, src_port, dst_ip, dst_port);

    process_dns(dns_payload, dns_payload_len);
}

static void process_ipv4(
    const uint8_t *ip,
    size_t captured_len
)
{
    if (captured_len < PACKET_IPV4_MIN_HEADER_SIZE) {
        return;
    }

    uint8_t version = ip[0] >> 4;
    size_t header_len = (ip[0] & 0x0F) * 4;

    if (version != 4 || header_len < PACKET_IPV4_MIN_HEADER_SIZE) {
        return;
    }

    if (captured_len < header_len) {
        return;
    }

    uint16_t total_len = read_be16(ip + 2);

    if (total_len < header_len || total_len > captured_len) {
        return;
    }

    uint16_t fragment_field = read_be16(ip + 6);

    if ((fragment_field & PACKET_IPV4_FRAGMENT_MASK) != 0) {
        return;
    }

    uint8_t protocol = ip[9];

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, ip + 12, src_ip, sizeof(src_ip)) == NULL ||
        inet_ntop(AF_INET, ip + 16, dst_ip, sizeof(dst_ip)) == NULL) {
        return;
    }

    if (protocol == PACKET_IPV4_PROTOCOL_UDP) {
        process_udp(
            ip + header_len,
            total_len - header_len,
            src_ip,
            dst_ip
        );
    }    
}

void packet_process(
    int link_type,
    const uint8_t *packet,
    size_t captured_len,
    size_t original_len
)
{
    if (packet == NULL) {
        return;
    }

    if (link_type != DLT_EN10MB) {
        fprintf(stderr, "Unsupported link type: %d\n", link_type);
        return;
    }

    if (captured_len < PACKET_ETHERNET_HEADER_SIZE) {
        return;
    }

    if (captured_len < original_len) {
        fprintf(stderr, "Warning: captured packet is truncated\n");
    }

    uint16_t ether_type = read_be16(packet + 12);
    if (ether_type == PACKET_ETHERTYPE_IPV4) {
        process_ipv4(
            packet + PACKET_ETHERNET_HEADER_SIZE,
            captured_len - PACKET_ETHERNET_HEADER_SIZE
        );
    }
}
