#include "rte_byteorder.h"
#include <arpa/inet.h> // For inet_pton
#include <netinet/in.h> // For in_addr
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_mbuf_ptype.h>
#include <rte_net.h>
#include <rte_mbuf.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_log.h>
#include <rte_common.h>
#include <rte_string_fns.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <rte_launch.h>
#define NB_RX_DESC     1024
#define NB_TX_DESC     1024
#define NB_MBUF        8192

static struct rte_mempool *mbuf_pool = NULL;

uint16_t src_port = 0; // Source port (input)
uint16_t internal_port = 1; // Destination port 1 (output)
uint16_t external_port = 2; // Destination port 2 (output)
struct in_addr internal_subnet;
uint32_t num_packets = 0;
uint32_t subnet_mask = 0;
uint16_t nb_queues = 0;
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


void
init_ports(){
    nb_queues = rte_lcore_count() - 1;
    printf("Using %u queues per port\n", nb_queues);
    
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 1) {
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");
    }
    
    if (src_port >= nb_ports || internal_port >= nb_ports || external_port >= nb_ports
        || src_port == internal_port || src_port == external_port || internal_port == external_port) {
        rte_exit(EXIT_FAILURE, "Invalid port configuration (nb_ports: %u)\n", nb_ports);
    }
    
    // enable rss mode
    struct rte_eth_conf port_conf = {0};
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    
    for (uint16_t port_id = 0; port_id < nb_ports; port_id++) {        
        struct rte_eth_dev_info dev_info;
        int ret = rte_eth_dev_info_get(port_id, &dev_info);
        if (ret != 0) {
            rte_exit(EXIT_FAILURE, "Error getting device info for port %u: %s\n",
                    port_id, strerror(-ret));
        }
        
        port_conf.rx_adv_conf.rss_conf.rss_hf = dev_info.flow_type_rss_offloads;
        printf("Port %u: RSS supported hash types = 0x%" PRIx64 "\n", port_id, dev_info.flow_type_rss_offloads);
        printf("Port %u: RSS hash mask being applied = 0x%" PRIx64 "\n", port_id, port_conf.rx_adv_conf.rss_conf.rss_hf);

        ret = rte_eth_dev_configure(port_id, nb_queues, nb_queues, &port_conf);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "Cannot configure port %u, err=%d (%s)\n", 
                     port_id, ret, strerror(-ret));
        }
        uint16_t actual_nb_rx_queues = nb_queues;
        uint16_t actual_nb_tx_queues = nb_queues;
        
        if (actual_nb_rx_queues > dev_info.max_rx_queues) {
            actual_nb_rx_queues = dev_info.max_rx_queues;
            printf("Port %u: limiting RX queues to max supported (%u)\n", 
                   port_id, actual_nb_rx_queues);
        }
        
        if (actual_nb_tx_queues > dev_info.max_tx_queues) {
            actual_nb_tx_queues = dev_info.max_tx_queues;
            printf("Port %u: limiting TX queues to max supported (%u)\n", 
                   port_id, actual_nb_tx_queues);
        }
        for (uint16_t q = 0; q < actual_nb_tx_queues; q++) {
            ret = rte_eth_tx_queue_setup(port_id, q, NB_TX_DESC, rte_eth_dev_socket_id(port_id), &dev_info.default_txconf);
            if (ret < 0) {
                rte_exit(EXIT_FAILURE, "Cannot setup TX queue %u for port %u, err=%d (%s)\n",
                         q, port_id, ret, strerror(-ret));
            }
        }
        
        for (uint16_t q = 0; q < actual_nb_rx_queues; q++) {
            ret = rte_eth_rx_queue_setup(port_id, q, NB_RX_DESC, rte_eth_dev_socket_id(port_id), &dev_info.default_rxconf, mbuf_pool);
            if (ret < 0) {
                rte_exit(EXIT_FAILURE, "Cannot setup RX queue %u for port %u, err=%d (%s)\n",
                         q, port_id, ret, strerror(-ret));
            }
        }
        ret = rte_eth_dev_start(port_id);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "Cannot start port %u, err=%d (%s)\n",
                     port_id, ret, strerror(-ret));
        }
        
        rte_eth_promiscuous_enable(port_id);
        
        printf("Port %u initialized with %u RX and %u TX queues\n", 
               port_id, actual_nb_rx_queues, actual_nb_tx_queues);
}
}

static int
worker(void *arg)
{
    uint16_t port_id = (uint16_t)(uintptr_t)arg;
    struct rte_mbuf *bufs[32];
    uint16_t nb_rx;

    printf("Worker running on lcore %u for port %u\n", rte_lcore_id(), port_id);

    while (1) {
        for (uint16_t queue_id = 0; queue_id < nb_queues; queue_id++) {
            nb_rx = rte_eth_rx_burst(port_id, queue_id, bufs, RTE_DIM(bufs));
            if (nb_rx > 0) {
                for (uint16_t i = 0; i < nb_rx; i++) {
                    struct rte_mbuf *mbuf = bufs[i];
                    rte_pktmbuf_free(mbuf); // Free the packet after processing
                }
            }
        }
    }

    return 0;
}

int
main(int argc, char **argv)
{
    int ret;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    argc -= ret;
    argv += ret;

    parse_args(argc, argv);

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NB_MBUF * (rte_lcore_count() - 1), 250, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }

    init_ports();

    unsigned lcore_id;
    uint16_t port_id = src_port;

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(worker, (void *)(uintptr_t)port_id, lcore_id);
    }

    worker((void *)(uintptr_t)port_id); // Run on the main lcore

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_wait_lcore(lcore_id);
    }

    return 0;
}