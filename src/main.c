#include <stdio.h>
#include <unistd.h>

#include "capture.h"
#include "packet.h"

#ifndef QUERYTRAIL_VERSION
#define QUERYTRAIL_VERSION "unknown"
#endif

static void print_usage(const char *program)
{
    fprintf(stderr, "Usage: sudo %s\n", program);
}

int main(int argc, char *argv[])
{
    printf("querytrail v%s\n", QUERYTRAIL_VERSION);

    if (geteuid() != 0) {
        fprintf(stderr, "Error: querytrail must be run with elevated privileges.\n");
        print_usage(argv[0]);
        return 1;
    }

    if (argc != 1) {
        fprintf(stderr, "Error: unexpected arguments.\n");
        print_usage(argv[0]);
        return 1;
    }

    return capture_run("en0", packet_process);
}