#include <arpa/inet.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <pcap/pcap.h>

#include "capture.h"

#define CAPTURE_SNAPSHOT_LENGTH 65535
#define CAPTURE_PROMISCUOUS_MODE 0
#define CAPTURE_READ_TIMEOUT_MS 1000


int capture_run(
    const char *interface,
    capture_packet_handler handler
)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(
        interface,
        CAPTURE_SNAPSHOT_LENGTH,
        CAPTURE_PROMISCUOUS_MODE,
        CAPTURE_READ_TIMEOUT_MS,
        errbuf
    );

    if (handle == NULL) {
        fprintf(stderr, "Failed to open interface: %s\n", errbuf);
        return 1;
    }

    int link_type = pcap_datalink(handle);

    if (link_type == -1) {
        fprintf(stderr, "Could not determine link type: %s\n",
                pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    printf("Successfully opened %s\n", interface);

    printf("Link type: %s\n",
        pcap_datalink_val_to_name(link_type));

    printf("Description: %s\n",
        pcap_datalink_val_to_description(link_type));

    struct pcap_pkthdr *header;
    const u_char *packet;

    while (1) {
        int result = pcap_next_ex(handle, &header, &packet);

        if (result == 1) {
            handler(
                link_type,
                packet,
                header->caplen,
                header->len
            );
        } else if (result == 0) {
            continue;
        } else if (result == -1) {
            fprintf(stderr, "Capture error: %s\n",
                    pcap_geterr(handle));
            break;
        } else if (result == -2) {
            break;
        }
    }

    pcap_close(handle);

    return 0;
}