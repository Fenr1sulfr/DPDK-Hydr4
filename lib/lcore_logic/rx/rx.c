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

#define MAX_PORTS 3
#define PKT_BURST 32
#define NUM_WORKERS 5  // Increased to 5 workers
#define RING_SIZE 4096
#define DEBUG_PRINT 1  // Set to 1 to enable debug prints

static struct rte_mempool *mbuf_pool = NULL;
static struct rte_ring *worker_rings[NUM_WORKERS] = {NULL};

uint16_t src_port = 0;         // Source port (input)
uint16_t internal_port = 1;    // Destination port 1 (output)
uint16_t external_port = 2;    // Destination port 2 (output)
struct in_addr internal_subnet;
uint32_t num_packets = 0;      // Number of times to send each packet
uint32_t subnet_mask = 0;
volatile uint8_t quit_signal = 0;

// Statistics
// struct worker_stats {
//     uint64_t packets_processed;
//     uint64_t packets_sent;
//     uint64_t packets_dropped;
// } __rte_cache_aligned;

// static struct worker_stats workers_stats[NUM_WORKERS];

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
    
    if (DEBUG_PRINT) {
        printf("Configuration:\n");
        printf("  Source port: %u\n", src_port);
        printf("  Internal port: %u\n", internal_port);
        printf("  External port: %u\n", external_port);
        printf("  Internal subnet: %s\n", inet_ntoa(internal_subnet));
        printf("  Subnet mask: 0x%x\n", subnet_mask);
        printf("  Num packets: %u\n", num_packets);
    }
}

int
init_ports()
{
    uint16_t port_id;
    
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_RSS,
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = NULL, // Default RSS key
                // .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP,
            },
        },
    };
        struct rte_eth_dev_info dev_info;
    

    // Initialize source port (input)
    if (rte_eth_dev_info_get(src_port, &dev_info) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to get port info for port %u\n", src_port);
    }

    if (rte_eth_dev_configure(src_port, 4, 4, &port_conf) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to configure port %u\n", src_port);
    }

    for (int q = 0; q < 4; q++) {
        if (rte_eth_rx_queue_setup(src_port, q, 512, rte_socket_id(), NULL, mbuf_pool) != 0) {
            rte_exit(EXIT_FAILURE, "Failed to setup Rx queue %d for port %u\n", q, src_port);
        }
    }
    
    
    // Add multiple TX queues per port - configure additional queues
    if (rte_eth_tx_queue_setup(src_port, 0, 1024, rte_socket_id(), NULL) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to setup Tx queue for port %u\n", src_port);
    }

    if (rte_eth_dev_start(src_port) < 0) {
        rte_exit(EXIT_FAILURE, "Failed to start port %u\n", src_port);
    }

    rte_eth_promiscuous_enable(src_port);
    
    // Initialize destination ports (output)
    for (port_id = 0; port_id < MAX_PORTS; port_id++) {
        if (port_id == src_port)
            continue;

        if (rte_eth_dev_info_get(port_id, &dev_info) != 0) {
            rte_exit(EXIT_FAILURE, "Failed to get port info for port %u\n", port_id);
        }

        if (rte_eth_dev_configure(port_id, 1, 1, &port_conf) != 0) {
            rte_exit(EXIT_FAILURE, "Failed to configure port %u\n", port_id);
        }

        if (rte_eth_rx_queue_setup(port_id, 0, 128, rte_socket_id(), NULL, mbuf_pool) != 0) {
            rte_exit(EXIT_FAILURE, "Failed to setup Rx queue for port %u\n", port_id);
        }

        if (rte_eth_tx_queue_setup(port_id, 0, 128, rte_socket_id(), NULL) != 0) {
            rte_exit(EXIT_FAILURE, "Failed to setup Tx queue for port %u\n", port_id);
        }

        if (rte_eth_dev_start(port_id) < 0) {
            rte_exit(EXIT_FAILURE, "Failed to start port %u\n", port_id);
        }
    }

    if (DEBUG_PRINT) {
        printf("All ports initialized successfully\n");
    }
    return 0;
}

// Function to send a single packet multiple times
static void
send_packet_multiple_times(struct rte_mbuf *pkt, uint16_t port_id, uint16_t *port_value, 
                          uint32_t count, uint16_t worker_id)
{
    uint32_t sent = 0;
    uint32_t i;
    
    // Update the reference count to account for multiple sends
    // This ensures the packet is not freed until we're done with all sends
    if (count > 1) {
        rte_pktmbuf_refcnt_update(pkt, count - 1);
    }
    
    for (i = 0; i < count; i++) {
        struct rte_mbuf *clone = pkt;
        
        // Modify port number for each copy if needed
        if (port_value != NULL) {
            if (*port_value == UINT16_MAX)
                *port_value = rte_bswap16(1);
            else
                *port_value = rte_bswap16(rte_bswap16(*port_value) + 1);
        }
        
        // Try to send the packet
        if (rte_eth_tx_burst(port_id, 0, &clone, 1) != 0) {
            sent++;
            // workers_stats[worker_id].packets_sent++;
        } else {
            // workers_stats[worker_id].packets_dropped++;
            // Don't free the packet here since the reference count is managing it
        }
    }
    
    // No need to manually free - the reference count system will handle it
    // The packet will be freed automatically when its ref count reaches 0
}

// Function to process each packet
static void
process_packet(struct rte_mbuf *pkt, uint16_t worker_id)
{
    struct rte_net_hdr_lens hdr_lens = {0};
    uint32_t ptype = rte_net_get_ptype(pkt, &hdr_lens, RTE_PTYPE_ALL_MASK);
    
    if (!RTE_ETH_IS_IPV4_HDR(ptype)) {
        // If not IPv4, send to external port
        send_packet_multiple_times(pkt, external_port, NULL, num_packets, worker_id);
        return;
    }
    
    struct rte_ipv4_hdr *ip_hdr = 
            rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, hdr_lens.l2_len);
    
    // Determine if the packet matches the internal subnet
    bool is_internal = (ip_hdr->src_addr & subnet_mask) == 
                       (internal_subnet.s_addr & subnet_mask);
    
    if (ptype & RTE_PTYPE_L4_UDP) {
        struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(
                pkt, struct rte_udp_hdr *, hdr_lens.l2_len + hdr_lens.l3_len);
                
        if (is_internal) {
            send_packet_multiple_times(pkt, internal_port, &udp_hdr->src_port, 
                                      num_packets, worker_id);
        } else {
            send_packet_multiple_times(pkt, external_port, &udp_hdr->dst_port, 
                                      num_packets, worker_id);
        }
        return;
    } else if (ptype & RTE_PTYPE_L4_TCP) {
        struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(
                pkt, struct rte_tcp_hdr *, hdr_lens.l2_len + hdr_lens.l3_len);
                
        if (is_internal) {
            send_packet_multiple_times(pkt, internal_port, &tcp_hdr->src_port, 
                                      num_packets, worker_id);
        } else {
            send_packet_multiple_times(pkt, external_port, &tcp_hdr->dst_port, 
                                      num_packets, worker_id);
        }
        return;
    }
    
    // Default case: send to external port
    send_packet_multiple_times(pkt, external_port, NULL, num_packets, worker_id);
}

// Function to receive packets and distribute to worker threads
static int
rx_thread(void *arg)
{
    struct rte_mbuf *pkts[PKT_BURST];
    unsigned i;
    uint16_t worker_idx = 0;
    uint64_t total_rx = 0;
    uint64_t total_enqueued = 0;
    uint64_t total_dropped = 0;
    uint64_t stats_counter = 0;

    printf("Rx thread started on core %u\n", rte_lcore_id());
    
    while (!quit_signal) {
        // Print stats periodically
        // stats_counter++;
        // if (DEBUG_PRINT && stats_counter >= 1000000) {
        //     printf("\nRx Stats: received=%lu, enqueued=%lu, dropped=%lu\n", 
        //           total_rx, total_enqueued, total_dropped);
            
        //     for (int w = 0; w < NUM_WORKERS; w++) {
        //         printf("Worker %d: processed=%lu, sent=%lu, dropped=%lu\n",
        //               w, workers_stats[w].packets_processed, 
        //               workers_stats[w].packets_sent, 
        //               workers_stats[w].packets_dropped);
        //     }
        //     stats_counter = 0;
        // }
        
        // Receive packets on the source port
        for (int q = 0; q < 4; q++) {
            uint16_t num_rx = rte_eth_rx_burst(src_port, q, pkts, PKT_BURST);
       
        
        if (num_rx > 0) {
            // if (DEBUG_PRINT && num_rx > 0) {
            //     printf("Received %u packets\n", num_rx);
            // }
            
            total_rx += num_rx;
            
            // Distribute packets to workers in a round-robin fashion
            for (i = 0; i < num_rx; i++) {
                // Try to enqueue to current worker
                if (rte_ring_enqueue(worker_rings[worker_idx], pkts[i]) == 0) {
                    total_enqueued++;
                } else {
                    // If the ring is full, free the packet
                    rte_pktmbuf_free(pkts[i]);
                    total_dropped++;
                }
                
                // Round-robin to next worker
                worker_idx = (worker_idx + 1) % NUM_WORKERS;
            }
        }
    }
}
    
    return 0;
}

// Function for worker threads to process packets
static int
worker_thread(void *arg)
{
    uint16_t worker_id = (uintptr_t)arg;
    struct rte_mbuf *pkts[PKT_BURST];
    unsigned int count, i;
    uint64_t idle_cycles = 0;
    
    printf("Worker %u started on core %u\n", worker_id, rte_lcore_id());
    
    while (!quit_signal) {
        // Dequeue up to PKT_BURST packets from the ring
        count = rte_ring_dequeue_burst(worker_rings[worker_id], (void **)pkts, PKT_BURST, NULL);
        
        if (count > 0) {
            idle_cycles = 0;
            
            for (i = 0; i < count; i++) {
                // workers_stats[worker_id].packets_processed++;
                process_packet(pkts[i], worker_id);
            }
        } else {
            idle_cycles++;
            if (DEBUG_PRINT && idle_cycles >= 10000000) {
                printf("Worker %u: Waiting for packets...\n", worker_id);
                idle_cycles = 0;
            }
        }
    }
    
    return 0;
}

int
main(int argc, char **argv)
{
    int ret;
    unsigned lcore_id;
    uint16_t i;
    char ring_name[32];

    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization: %s\n",
                rte_strerror(rte_errno));
    }
    argc -= ret;
    argv += ret;

    // Check if we have enough lcores for our threads (1 rx + NUM_WORKERS)
    unsigned int required_lcores = 1 + NUM_WORKERS;
    unsigned int available_lcores = 0;
    
    RTE_LCORE_FOREACH(lcore_id) {
        available_lcores++;
    }
    
    if (available_lcores < required_lcores) {
        rte_exit(EXIT_FAILURE, "Not enough cores available. Need %u, have %u\n", 
                 required_lcores, available_lcores);
    }

    // Create the memory pool - increased size to handle multiple workers and multiple sends
    mbuf_pool = rte_pktmbuf_pool_create(
            "mbuf_pool", 
            8192 * NUM_WORKERS * 2, // Double the size to handle multiple sends
            256, 
            0, 
            RTE_MBUF_DEFAULT_BUF_SIZE, 
            rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Error creating memory pool: %s\n", 
                 rte_strerror(rte_errno));
    }

    // Initialize stats
    // memset(workers_stats, 0, sizeof(workers_stats));

    // Create rings for worker threads
    for (i = 0; i < NUM_WORKERS; i++) {
        snprintf(ring_name, sizeof(ring_name), "worker_ring_%u", i);
        worker_rings[i] = rte_ring_create(ring_name, RING_SIZE, 
                                         rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (worker_rings[i] == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to create ring %s: %s\n", 
                     ring_name, rte_strerror(rte_errno));
        }
    }

    parse_args(argc, argv);

    // Initialize network ports
    init_ports();

    // Start worker threads
    int core_count = 0;
    lcore_id = rte_get_next_lcore(-1, 1, 0);
    for (i = 0; i < NUM_WORKERS; i++) {
        if (lcore_id == RTE_MAX_LCORE) {
            rte_exit(EXIT_FAILURE, "Not enough cores available\n");
        }
        
        ret = rte_eal_remote_launch(worker_thread, (void *)(uintptr_t)i, lcore_id);
        if (ret != 0) {
            rte_exit(EXIT_FAILURE, "Failed to launch worker on core %u\n", lcore_id);
        }
        
        printf("Launched worker %u on core %u\n", i, lcore_id);
        core_count++;
        lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    }

    // Start RX thread on the main core
    rx_thread(NULL);

    // Wait for all worker threads to complete
    rte_eal_mp_wait_lcore();

    // Clean up resources
    for (i = 0; i < NUM_WORKERS; i++) {
        rte_ring_free(worker_rings[i]);
    }

    return 0;
}