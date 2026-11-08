#ifndef QUERYTRAIL_PACKET_H
#define QUERYTRAIL_PACKET_H

#include <stddef.h>
#include <stdint.h>

void packet_process(
    int link_type,
    const uint8_t *packet,
    size_t captured_len,
    size_t original_len
);

#endif
