#include <arpa/inet.h> // For inet_pton
#include <netinet/in.h> // For in_addr
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_lcore.h>
#include <rte_net.h>
#include <rte_atomic.h>
#include <signal.h>
#include <stdbool.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>


#define BURST_SIZE     32
#define NB_MBUF        8192
#define NB_RX_DESC     1024
#define NB_TX_DESC     1024

static rte_atomic16_t next_queue_id;

struct rte_mempool *mbuf_pool;
volatile bool force_quit = false;
uint16_t nb_queues = 0;

uint16_t src_port = 0;
uint16_t internal_port = 1;
uint16_t external_port = 2;
int num_packets = 1;
uint32_t subnet_mask = 0;
struct in_addr internal_subnet;

void
signal_handler(int signum) 
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal received, preparing to exit...\n");
        force_quit = true;
    }
}

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
    printf("%s", ip_str);

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
    while ((opt = getopt(argc, argv, "n:S:I:E:i:")) != -1) {
        switch (opt) {
            case 'n': 
                num_packets = atoi(optarg);
                if (num_packets > 500) num_packets = 500;
                else if (num_packets <= 0) num_packets = 1;
                break;
            case 'S':
                src_port = atoi(optarg);
                break;
            case 'I':
                internal_port = atoi(optarg);
                break;
            case 'E':
                external_port = atoi(optarg);
                break;
            case 'i':
                parse_cidr(optarg, &internal_subnet, &subnet_mask);
                break;
            default:
                fprintf(stderr, "Usage: %s -n <num_packets> -S <src_port> -I <internal_port> -E <external_port> -i <internal_subnet>\n", 
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    
    printf("Configuration: packets=%d, src=%u, internal=%u, external=%u\n", 
           num_packets, src_port, internal_port, external_port);
}

void
init_ports()
{
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

static uint64_t
process_packet_batched(struct rte_mbuf **pkts, uint16_t nb_rx, uint16_t queue_id)
{
    uint64_t sent_total = 0;

    for (int i = 0; i < nb_rx; i++) {
        struct rte_mbuf *pkt = pkts[i];
        struct rte_net_hdr_lens hdr_lens;
	    uint32_t ptype = rte_net_get_ptype(pkt, &hdr_lens, RTE_PTYPE_ALL_MASK);

        // Fast-forward non-IPv4
        if (!RTE_ETH_IS_IPV4_HDR(ptype)) {
            if (rte_eth_tx_burst(external_port, queue_id, &pkt, 1) == 0) {
                rte_pktmbuf_free(pkt);
            }

            continue;
        }

        struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, hdr_lens.l2_len);
        uint8_t proto = ip_hdr->next_proto_id;

        // Fast-forward non-TCP/UDP
        if (proto != IPPROTO_UDP && proto != IPPROTO_TCP) {
            if (rte_eth_tx_burst(external_port, queue_id, &pkt, 1) == 0) {
                rte_pktmbuf_free(pkt);
            }

            continue;
        }

        //determine target_port
        uint32_t src_ip = rte_be_to_cpu_32(ip_hdr->src_addr);
        uint32_t subnet_ip = rte_be_to_cpu_32(internal_subnet.s_addr);
        bool is_internal = (src_ip & subnet_mask) == (subnet_ip & subnet_mask);
        uint16_t target_port = is_internal ? internal_port : external_port;

        struct rte_mbuf *clone_batch[num_packets];
        uint16_t nb_clones = 0;
        clone_batch[nb_clones++] = pkt;

        uint16_t orig_port = 0;
        void *l4_hdr = (uint8_t *)ip_hdr + (ip_hdr->version_ihl & 0x0F) * 4;

        if (proto == IPPROTO_UDP) {
            orig_port = rte_be_to_cpu_16(((struct rte_udp_hdr *)l4_hdr)->src_port);
        } else {
            orig_port = rte_be_to_cpu_16(((struct rte_tcp_hdr *)l4_hdr)->src_port);
        }

        for (int j = 1; j < num_packets; j++) {
            struct rte_mbuf *copy = rte_pktmbuf_copy(pkt, mbuf_pool, 0, UINT32_MAX);
            if (!copy) continue;

            struct rte_ipv4_hdr *c_ip = rte_pktmbuf_mtod_offset(copy, struct rte_ipv4_hdr *, hdr_lens.l2_len);
            void *c_l4_hdr = (uint8_t *)c_ip + (c_ip->version_ihl & 0x0F) * 4;

            uint16_t new_port = orig_port + j;

            if (proto == IPPROTO_UDP) {
                ((struct rte_udp_hdr *)c_l4_hdr)->src_port = rte_cpu_to_be_16(new_port);
            } else {
                ((struct rte_tcp_hdr *)c_l4_hdr)->src_port = rte_cpu_to_be_16(new_port);
            }

            clone_batch[nb_clones++] = copy;
        }

        struct rte_mbuf *tx_batch[BURST_SIZE];
        uint16_t tx_count = 0;

        for (uint16_t i = 0; i < nb_clones; i++) {
            tx_batch[tx_count++] = clone_batch[i];

            if (tx_count == BURST_SIZE) {
                uint16_t sent = rte_eth_tx_burst(target_port, queue_id, tx_batch, tx_count);
                sent_total += sent;

                for (uint16_t k = sent; k < tx_count; k++)
                    rte_pktmbuf_free(tx_batch[k]);

                tx_count = 0;
            }
        }

        if (tx_count > 0) {
            uint16_t sent = rte_eth_tx_burst(target_port, queue_id, tx_batch, tx_count);
            sent_total += sent;

            for (uint16_t k = sent; k < tx_count; k++)
                rte_pktmbuf_free(tx_batch[k]);
        }
    }

    return sent_total;
}


int
lcore_worker()
{
    uint16_t lcore_id = rte_lcore_id();
    uint16_t queue_id = rte_atomic16_add_return(&next_queue_id, 1) - 1;

    struct rte_mbuf *pkts[BURST_SIZE];
    uint64_t total_rx = 0;
    uint64_t total_tx = 0;

    while (!force_quit) {
        uint16_t nb_rx = rte_eth_rx_burst(src_port, queue_id, pkts, BURST_SIZE);
        if (nb_rx == 0) continue;

        total_rx += nb_rx;
        total_tx += process_packet_batched(pkts, nb_rx, queue_id);
    }

    printf("Lcore %u exiting. Final RX: %lu | TX: %lu\n", lcore_id, total_rx, total_tx);
    return 0;
}

int 
main(int argc, char **argv)
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "EAL initialization failed\n");
    }
    
    // Shift args by ret
    argc -= ret;
    argv += ret;
    
    parse_args(argc, argv);

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NB_MBUF * (rte_lcore_count() - 1), 250, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }
    
    init_ports();
    
    printf("\nPacket multiplier running with %d cores\n", rte_lcore_count());
    
    unsigned lcore_id;
    rte_atomic16_init(&next_queue_id);
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(lcore_worker, NULL, lcore_id);
    }
    
    printf("\nTraffic multiplication started - press Ctrl+C to exit\n");
    
    rte_eal_mp_wait_lcore();
    
    rte_eth_dev_stop(src_port);
    rte_eth_dev_close(src_port);
    
    if (internal_port != src_port) {
        rte_eth_dev_stop(internal_port);
        rte_eth_dev_close(internal_port);
    }
    
    printf("Application exited cleanly\n");
    return 0;
}