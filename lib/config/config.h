#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

extern uint16_t src_port;
extern uint16_t internal_port;
extern uint16_t external_port;
extern uint32_t num_packets;
extern uint32_t subnet_mask;
extern struct in_addr internal_subnet;

void parse_args(int argc, char **argv);

#endif // CONFIG_H