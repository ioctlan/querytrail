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
void test_dns_format_cname(void);
void test_dns_format_compressed_cname(void);
void test_dns_cname_wrong_type(void);
void test_dns_cname_invalid_rdlength(void);
void test_dns_cname_rdlength_mismatch(void);
void test_dns_cname_invalid_pointer(void);
void test_dns_parse_message(void);
void test_dns_message_multiple_questions(void);
void test_dns_message_multiple_answers(void);
void test_dns_message_malformed_question(void);
void test_dns_message_trailing_bytes(void);
void test_dns_free_message(void);

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
    test_dns_format_cname();
    test_dns_format_compressed_cname();
    test_dns_cname_wrong_type();
    test_dns_cname_invalid_rdlength();
    test_dns_cname_rdlength_mismatch();
    test_dns_cname_invalid_pointer();
    test_dns_parse_message();
    test_dns_message_multiple_questions();
    test_dns_message_multiple_answers();
    test_dns_message_malformed_question();
    test_dns_message_trailing_bytes();
    test_dns_free_message();

    printf("\nAll tests passed!\n");

    return 0;
}