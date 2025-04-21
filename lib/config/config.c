#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h> // For inet_pton
#include <netinet/in.h> // For in_addr
#include <libconfig.h> // For YAML parsing

uint16_t src_port = 0;
uint16_t internal_port = 1;
uint16_t external_port = 2;
struct in_addr internal_subnet;
uint32_t num_packets = 0;
uint32_t subnet_mask = 0;

void parse_cidr(const char *cidr, struct in_addr *subnet, uint32_t *mask) {
    char ip_str[INET_ADDRSTRLEN];
    char *slash_pos = strchr(cidr, '/');
    if (slash_pos == NULL) {
        fprintf(stderr, "Invalid CIDR format: %s\n", cidr);
        exit(EXIT_FAILURE);
    }

    // Extract IP address and prefix length
    size_t ip_len = slash_pos - cidr;
    strncpy(ip_str, cidr, ip_len);
    ip_str[ip_len] = '\0';

    int prefix_len = atoi(slash_pos + 1);
    if (prefix_len < 0 || prefix_len > 32) {
        fprintf(stderr, "Invalid prefix length in CIDR: %s\n", cidr);
        exit(EXIT_FAILURE);
    }

    // Convert IP to binary form
    if (inet_pton(AF_INET, ip_str, subnet) != 1) {
        fprintf(stderr, "Invalid IP address in CIDR: %s\n", cidr);
        exit(EXIT_FAILURE);
    }

    // Calculate subnet mask
    *mask = htonl(~((1 << (32 - prefix_len)) - 1));
}

void parse_yaml(const char *filename) {
    //Custom types from libconfig.h
    config_t cfg; 
    config_setting_t *setting;
    const char *str;
    config_init(&cfg);
    if (!config_read_file(&cfg, filename)) {
        fprintf(stderr, "Error reading config file: %s\n", config_error_file(&cfg));
        config_destroy(&cfg);
        return(exit(EXIT_FAILURE));
    }
   if(config_lookup_int(&cfg, "src_port", &src_port) == CONFIG_FALSE) {
        fprintf(stderr, "Error reading src_port from config file\n");
        config_destroy(&cfg);
        return(exit(EXIT_FAILURE));
    }
    if(config_lookup_int(&cfg, "internal_port", &internal_port) == CONFIG_FALSE) {
        fprintf(stderr, "Error reading internal_port from config file\n");
        config_destroy(&cfg);
        return(exit(EXIT_FAILURE));
    }
    if(config_lookup_int(&cfg, "external_port", &external_port) == CONFIG_FALSE) {
        fprintf(stderr, "Error reading external_port from config file\n");
        config_destroy(&cfg);
        return(exit(EXIT_FAILURE));
    }
    if(config_lookup_string(&cfg, "internal_subnet", &str) == CONFIG_FALSE) {
        parse_cidr(str, &internal_subnet, &subnet_mask);
        fprintf(stderr, "Error reading internal_subnet from config file\n");
        config_destroy(&cfg);
        return(exit(EXIT_FAILURE));
    }
    parse_cidr(str, &internal_subnet, &subnet_mask);
    if(config_lookup_int(&cfg, "num_packets", &num_packets) == CONFIG_FALSE) {
        fprintf(stderr, "Error reading num_packets from config file\n");
        config_destroy(&cfg);
        return(exit(EXIT_FAILURE));
    }
    config_destroy(&cfg);
}

