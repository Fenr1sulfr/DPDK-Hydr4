// gcc ./lib/config/config.test.c -o config_test -lconfig && ./config_test
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <libconfig.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "config.c"

void test_parse_cidr_valid() {
    struct in_addr subnet;
    uint32_t mask;
    const char *cidr = "192.168.1.0/24";

    parse_cidr(cidr, &subnet, &mask);

    char subnet_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &subnet, subnet_str, INET_ADDRSTRLEN);

    if (strcmp(subnet_str, "192.168.1.0") == 0 && ntohl(mask) == 0xFFFFFF00) {
        printf("test_parse_cidr_valid passed\n");
    } else {
        printf("test_parse_cidr_valid failed\n");
    }
}

void test_parse_cidr_invalid_format() {
    struct in_addr subnet;
    uint32_t mask;
    const char *cidr = "192.168.1.0";

    if (fork() == 0) { // Child process to test exit
        parse_cidr(cidr, &subnet, &mask);
        exit(EXIT_SUCCESS);
    } else {
        int status;
        wait(&status);
        if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE) {
            printf("test_parse_cidr_invalid_format passed\n");
        } else {
            printf("test_parse_cidr_invalid_format failed\n");
        }
    }
}

void test_parse_yaml_valid() {
    const char *filename = "local_test2.yaml";

    // Create a temporary config file
    FILE *file = fopen(filename, "w");
    fprintf(file,
            "src_port = 0;\n"
            "internal_port = 1;\n"
            "external_port = 2;\n"
            "internal_subnet = \"192.168.1.0/24\";\n"
            "num_packets = 100;\n");
    fclose(file);

    parse_yaml(filename);
    
    if (src_port == 0 && internal_port == 1 && external_port == 2 &&
        ntohl(subnet_mask) == 0xFFFFFF00 && num_packets == 100) {
        printf("test_parse_yaml_valid passed\n");
    } else {
        printf("test_parse_yaml_valid failed\n");
    }

    remove(filename); // Clean up
}

void test_parse_yaml_missing_field() {
    const char *filename = "local_test.yaml";

    // Create a temporary config file with missing fields
    FILE *file = fopen(filename, "w");
    fprintf(file,
            "src_port = 1234;\n"
            "internal_port = 5678;\n");
    fclose(file);

    if (fork() == 0) { // Child process to test exit
        parse_yaml(filename);
        exit(EXIT_SUCCESS);
    } else {
        int status;
        wait(&status);
        if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE) {
            printf("test_parse_yaml_missing_field passed\n");
        } else {
            printf("test_parse_yaml_missing_field failed\n");
        }
    }

    remove(filename); // Clean up
}

int main() {
    test_parse_cidr_valid();
    test_parse_cidr_invalid_format();
    test_parse_yaml_valid();
    test_parse_yaml_missing_field();
    return 0;
}