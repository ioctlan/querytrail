#include <stdio.h>

void test_dns_header(void);

int main(void)
{
    printf("Running QueryTrail tests...\n\n");

    test_dns_header();

    printf("\nAll tests passed!\n");

    return 0;
}