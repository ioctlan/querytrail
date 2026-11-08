#include <stdio.h>

#ifndef QUERYTRAIL_VERSION
#define QUERYTRAIL_VERSION "unknown"
#endif

int main(void)
{
    printf("QueryTrail v%s\n", QUERYTRAIL_VERSION);
    printf("DNS activity recorder for Linux\n");

    return 0;
}
