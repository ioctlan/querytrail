#include <stdio.h>

void test_dns_header(void);
void test_dns_question(void);
void test_dns_question_compression(void);
void test_dns_question_invalid_compression(void);
void test_dns_question_pointer_chain(void);

int main(void)
{
    printf("Running QueryTrail tests...\n\n");

    test_dns_header();
    test_dns_question();
    test_dns_question_compression();
    test_dns_question_invalid_compression();
    test_dns_question_pointer_chain();

    printf("\nAll tests passed!\n");

    return 0;
}