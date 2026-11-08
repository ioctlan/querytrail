#ifndef QUERYTRAIL_PRESENTATION_H
#define QUERYTRAIL_PRESENTATION_H

#include <stdint.h>
#include "dns.h"

void presentation_dns_message(
    const struct dns_message *message,
    const char *src_ip,
    uint16_t src_port,
    const char *dst_ip,
    uint16_t dst_port
);

#endif
