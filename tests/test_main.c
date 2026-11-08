#include <stdio.h>

void test_dns_header(void);
void test_dns_question(void);
void test_dns_question_compression(void);
void test_dns_question_invalid_compression(void);
void test_dns_question_pointer_chain(void);
void test_dns_resource_record(void);
void test_dns_resource_record_invalid(void);
void test_dns_format_a_record(void);
void test_dns_format_aaaa_record(void);
void test_dns_format_address_invalid(void);

int main(void)
{
    printf("Running QueryTrail tests...\n\n");

    test_dns_header();
    test_dns_question();
    test_dns_question_compression();
    test_dns_question_invalid_compression();
    test_dns_question_pointer_chain();
    test_dns_resource_record();
    test_dns_resource_record_invalid();
    test_dns_format_a_record();
    test_dns_format_aaaa_record();
    test_dns_format_address_invalid();

    printf("\nAll tests passed!\n");

    return 0;
}