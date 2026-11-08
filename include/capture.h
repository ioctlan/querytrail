#ifndef QUERYTRAIL_CAPTURE_H
#define QUERYTRAIL_CAPTURE_H

#include <stddef.h>
#include <stdint.h>

typedef void (*capture_packet_handler)(
    int link_type,
    const uint8_t *packet,
    size_t captured_len,
    size_t original_len
);

int capture_run(
    const char *interface,
    capture_packet_handler handler
);

#endif