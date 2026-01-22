#include <stdio.h>
#include <string.h>
#include "hash/sha1.h"

static void print_hex(const unsigned char* d, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", d[i]);
    putchar('\n');
}

int test_sha1_vector(const char* msg, const char* expected_hex) {
    sha1 ctx = sha1_hash((char*)msg, strlen(msg));

    char out[41];
    out[40] = '\0';
    for (int i = 0; i < 20; i++)
        sprintf(out + i * 2, "%02x", (unsigned char)ctx.digest[i]);
    printf("%s\n", out);

    return strcmp(out, expected_hex) == 0;
}

int main(void) {
    struct {
        const char* msg;
        const char* expected_hex;
    } test_vectors[] = {
        {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
        {"a", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"},
        {"0123456701234567012345670123456701234567012345670123456701234567", "e0c094e867ef46c350ef54a7f59dd60bed92ae83"}
    };
    int num_tests = sizeof(test_vectors);
    num_tests /= sizeof(test_vectors[0]);
    int r = 0;
    for(int i = 0; i < num_tests; i++) {
        if (test_sha1_vector(test_vectors[i].msg, test_vectors[i].expected_hex)) {
            printf("[+] Test %d passed.\n", i + 1);
        } else {
            printf("[-] Test %d failed!\n", i + 1);
            r = 1;
        }
    }
    return r;
}
