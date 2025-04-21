
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <stdbool.h>
#include <arpa/inet.h> // For inet_pton
#include <netinet/in.h> // For in_addr


uint16_t src_port = 0;
uint16_t internal_port = 1;
uint16_t external_port = 2;
struct in_addr internal_subnet;
uint32_t num_packets = 0;
uint32_t subnet_mask = 0;


void
parse_cidr(const char *cidr, struct in_addr *subnet, uint32_t *mask)
{
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

void
parse_args(int argc, char **argv)
{
	int opt;

	bool src_port_set = false;
	bool internal_port_set = false;
	bool external_port_set = false;

	while ((opt = getopt(argc, argv, "s:i:I:E:n:")) != -1) {
		switch (opt) {
		case 's':
			src_port = atoi(optarg);
			src_port_set = true;
			break;
		case 'i':
			parse_cidr(optarg, &internal_subnet, &subnet_mask);
			break;
		case 'I':
			internal_port = atoi(optarg);
			internal_port_set = true;
			break;
		case 'E':
			external_port = atoi(optarg);
			external_port_set = true;
			break;
		case 'n':
			num_packets = atoi(optarg);
			break;
		default:
			fprintf(stderr, "Usage: %s -s <src_port> -i <internal_subnet> -I <internal_port> -E <external_port> -n <num_packets>\n",
					argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (!src_port_set || subnet_mask == 0 || !internal_port_set || !external_port_set) {
		fprintf(stderr, "Invalid or missing arguments\n");
		exit(EXIT_FAILURE);
	}

	if (num_packets == 0) {
		num_packets = 1;
	}
}