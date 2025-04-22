#include <rte_byteorder.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_log.h>
#include <rte_common.h>
#include <rte_ring.h>
#include <rte_launch.h>

#define NB_RX_DESC     256        // Reduced descriptor size for virtual devices
#define NB_TX_DESC     256
#define NB_MBUF        8192       // Increased for virtual devices which may need more buffers
#define MBUF_CACHE_SIZE 256
#define RX_RING_SIZE   256
#define WORKER_RING_SIZE 128
#define BURST_SIZE     32
#define CACHE_SIZE     16
#define CACHE_TIMEOUT  1000000    // 1ms timeout

static struct rte_mempool *mbuf_pool = NULL;
static struct rte_ring *rx_ring = NULL;
static struct rte_ring **worker_rings = NULL;

uint16_t src_port = 0;
uint16_t internal_port = 1;
uint16_t external_port = 2;
struct in_addr internal_subnet;
uint32_t num_packets = 0;
uint32_t subnet_mask = 0;
uint16_t nb_queues = 0;
uint16_t nb_workers = 0;

// CIDR parsing - unchanged
void parse_cidr(const char *cidr, struct in_addr *subnet, uint32_t *mask) {
    char ip_str[INET_ADDRSTRLEN];
    char *slash_pos = strchr(cidr, '/');
    if (slash_pos == NULL) {
        fprintf(stderr, "Invalid CIDR format: %s\n", cidr);
        exit(EXIT_FAILURE);
    }

    size_t ip_len = slash_pos - cidr;
    strncpy(ip_str, cidr, ip_len);
    ip_str[ip_len] = '\0';

    int prefix_len = atoi(slash_pos + 1);
    if (prefix_len < 0 || prefix_len > 32) {
        fprintf(stderr, "Invalid prefix length in CIDR: %s\n", cidr);
        exit(EXIT_FAILURE);
    }

    if (inet_pton(AF_INET, ip_str, subnet) != 1) {
        fprintf(stderr, "Invalid IP address in CIDR: %s\n", cidr);
        exit(EXIT_FAILURE);
    }

    *mask = htonl(~((1 << (32 - prefix_len)) - 1));
    
    printf("Parsed subnet: %s/%d -> 0x%x, mask: 0x%x\n", 
           ip_str, prefix_len, subnet->s_addr, *mask);
}

// Argument parsing - unchanged but with debug output
void parse_args(int argc, char **argv) {
    int opt;
    bool src_port_set = false, internal_port_set = false, external_port_set = false;
    bool subnet_set = false;
    
    printf("Parsing arguments...\n");

    while ((opt = getopt(argc, argv, "s:i:I:E:n:")) != -1) {
        switch (opt) {
        case 's':
            src_port = atoi(optarg);
            src_port_set = true;
            printf("Source port set to: %u\n", src_port);
            break;
        case 'i':
            parse_cidr(optarg, &internal_subnet, &subnet_mask);
            subnet_set = true;
            break;
        case 'I':
            internal_port = atoi(optarg);
            internal_port_set = true;
            printf("Internal port set to: %u\n", internal_port);
            break;
        case 'E':
            external_port = atoi(optarg);
            external_port_set = true;
            printf("External port set to: %u\n", external_port);
            break;
        case 'n':
            num_packets = atoi(optarg);
            printf("Number of packets set to: %u\n", num_packets);
            break;
        default:
            fprintf(stderr, "Usage: %s -s <src_port> -i <internal_subnet> -I <internal_port> -E <external_port> -n <num_packets>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (!src_port_set || !subnet_set || !internal_port_set || !external_port_set) {
        fprintf(stderr, "Invalid or missing arguments\n");
        exit(EXIT_FAILURE);
    }

    if (num_packets == 0) {
        num_packets = 1;
        printf("Number of packets defaulted to: %u\n", num_packets);
    }
    
    printf("Arguments parsed successfully\n");
}

void init_ports() {
    printf("Initializing ports...\n");
    
    // For virtual devices, we should use fewer queues
    uint16_t nb_lcores = rte_lcore_count();
    printf("Available lcores: %u\n", nb_lcores);
    
    // Limit queues to a sensible number for virtual devices
    nb_queues = RTE_MIN(nb_lcores - 1, 2);  // Use at most 2 queues for virtual devices
    nb_workers = nb_queues;
    printf("Using %u queues and %u workers per port\n", nb_queues, nb_workers);

    uint16_t nb_ports = rte_eth_dev_count_avail();
    printf("Available ports: %u\n", nb_ports);
    
    if (nb_ports < 3) {
        rte_exit(EXIT_FAILURE, "Need at least 3 Ethernet ports, found %u\n", nb_ports);
    }

    if (src_port >= nb_ports || internal_port >= nb_ports || external_port >= nb_ports ||
        src_port == internal_port || src_port == external_port || internal_port == external_port) {
        rte_exit(EXIT_FAILURE, "Invalid port configuration (nb_ports: %u)\n", nb_ports);
    }

    // Simplified port configuration for virtual devices
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_NONE,  // Don't use RSS for virtual devices
        }
    };

    for (uint16_t port_id = 0; port_id < nb_ports; port_id++) {
        // Only configure ports we actually use
        if (port_id != src_port && port_id != internal_port && port_id != external_port) {
            continue;
        }
        
        printf("Configuring port %u...\n", port_id);
        
        struct rte_eth_dev_info dev_info;
        int ret = rte_eth_dev_info_get(port_id, &dev_info);
        if (ret != 0) {
            rte_exit(EXIT_FAILURE, "Error getting device info for port %u: %s\n", port_id, strerror(-ret));
        }

        printf("Port %u max_rx_queues: %u, max_tx_queues: %u\n", 
               port_id, dev_info.max_rx_queues, dev_info.max_tx_queues);

        // For virtual devices, use fewer queues than requested in command line
        uint16_t actual_nb_rx_queues = 1;  // Use single queue for virtual devices
        uint16_t actual_nb_tx_queues = 1;  // Use single queue for virtual devices

        printf("Configuring port %u with %u RX and %u TX queues\n", 
               port_id, actual_nb_rx_queues, actual_nb_tx_queues);
               
        ret = rte_eth_dev_configure(port_id, actual_nb_rx_queues, actual_nb_tx_queues, &port_conf);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "Cannot configure port %u, err=%d (%s)\n", port_id, ret, strerror(-ret));
        }

        for (uint16_t q = 0; q < actual_nb_rx_queues; q++) {
            printf("Setting up RX queue %u for port %u\n", q, port_id);
            ret = rte_eth_rx_queue_setup(port_id, q, NB_RX_DESC, rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
            if (ret < 0) {
                rte_exit(EXIT_FAILURE, "Cannot setup RX queue %u for port %u, err=%d (%s)\n", q, port_id, ret, strerror(-ret));
            }
        }

        for (uint16_t q = 0; q < actual_nb_tx_queues; q++) {
            printf("Setting up TX queue %u for port %u\n", q, port_id);
            ret = rte_eth_tx_queue_setup(port_id, q, NB_TX_DESC, rte_eth_dev_socket_id(port_id), NULL);
            if (ret < 0) {
                rte_exit(EXIT_FAILURE, "Cannot setup TX queue %u for port %u, err=%d (%s)\n", q, port_id, ret, strerror(-ret));
            }
        }

        printf("Starting port %u\n", port_id);
        ret = rte_eth_dev_start(port_id);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "Cannot start port %u, err=%d (%s)\n", port_id, ret, strerror(-ret));
        }

        printf("Enabling promiscuous mode on port %u\n", port_id);
        rte_eth_promiscuous_enable(port_id);
    }
    
    printf("Port initialization complete\n");
}

// Simplified RX thread for virtual devices
static int rx_thread(void *arg) {
    uint16_t port_id = (uint16_t)(uintptr_t)arg;
    struct rte_mbuf *bufs[BURST_SIZE];
    printf("RX thread running on lcore %u for port %u\n", rte_lcore_id(), port_id);

    while (1) {
        // Read from a single queue for virtual devices
        uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);
        if (nb_rx == 0) {
            rte_delay_us_block(10); // Short delay to avoid spinning
            continue;
        }
        
        printf("Received %u packets on port %u\n", nb_rx, port_id);
        
        // Process each received packet
        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *mbuf = bufs[i];
            
            // Create clones if needed
            for (uint16_t dup = 0; dup < num_packets; dup++) {
                struct rte_mbuf *clone;
                
                if (dup == 0 && num_packets == 1) {
                    // No need to clone if only one copy needed
                    clone = mbuf;
                } else {
                    // Use pktmbuf_clone for efficient duplication
                    clone = rte_pktmbuf_clone(mbuf, mbuf_pool);
                    if (!clone) {
                        printf("Failed to clone packet\n");
                        continue;
                    }
                }
                
                // Simple round-robin distribution to workers
                uint16_t worker_id = i % nb_workers;
                
                if (rte_ring_enqueue(worker_rings[worker_id], clone) != 0) {
                    printf("Failed to enqueue packet to worker %u\n", worker_id);
                    rte_pktmbuf_free(clone);
                }
            }
            
            // Free original mbuf if we created clones
            if (num_packets > 1) {
                rte_pktmbuf_free(mbuf);
            }
        }
    }
    return 0;
}

// Simplified worker thread for virtual devices
static int worker(void *arg) {
    uint16_t worker_id = (uint16_t)(uintptr_t)arg;
    struct rte_mbuf *bufs[BURST_SIZE];
    struct rte_mbuf *cache[CACHE_SIZE] = {0};
    uint64_t cache_times[CACHE_SIZE] = {0};
    uint16_t cache_count = 0;
    uint64_t now;

    printf("Worker %u running on lcore %u\n", worker_id, rte_lcore_id());

    while (1) {
        now = rte_rdtsc();
        
        // Process cached packets first
        for (uint16_t i = 0; i < cache_count; ) {
            if (now - cache_times[i] > CACHE_TIMEOUT) {
                struct rte_mbuf *mbuf = cache[i];
                
                // Get IP header - make sure packet is valid
                if (rte_pktmbuf_data_len(mbuf) < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)) {
                    printf("Packet too small for IP header\n");
                    rte_pktmbuf_free(mbuf);
                    // Remove from cache
                    cache[i] = cache[--cache_count];
                    cache_times[i] = cache_times[cache_count];
                    continue;
                }
                
                struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(
                    mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
                
                // Modify packet (example: increment TTL)
                ipv4_hdr->time_to_live++;
                
                // Determine destination port based on subnet
                uint16_t dst_port;
                if ((ipv4_hdr->dst_addr & subnet_mask) == internal_subnet.s_addr) {
                    dst_port = internal_port;
                } else {
                    dst_port = external_port;
                }
                
                printf("Worker %u sending packet to port %u\n", worker_id, dst_port);
                
                // Send packet
                if (rte_eth_tx_burst(dst_port, 0, &mbuf, 1) == 0) {
                    printf("Failed to send packet to port %u\n", dst_port);
                    rte_pktmbuf_free(mbuf);
                }
                
                // Remove from cache
                cache[i] = cache[--cache_count];
                cache_times[i] = cache_times[cache_count];
            } else {
                i++;
            }
        }
        
        // Process new packets from worker ring
        uint16_t nb_rx = rte_ring_dequeue_burst(worker_rings[worker_id], 
                                               (void **)bufs, 
                                               BURST_SIZE, NULL);
        if (nb_rx == 0) {
            rte_delay_us_block(10); // Short delay
            continue;
        }
        
        printf("Worker %u dequeued %u packets\n", worker_id, nb_rx);
        
        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *mbuf = bufs[i];
            
            // Add to cache if there's room
            if (cache_count < CACHE_SIZE) {
                cache[cache_count] = mbuf;
                cache_times[cache_count] = now;
                cache_count++;
            } else {
                // Process immediately if cache is full
                if (rte_pktmbuf_data_len(mbuf) < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)) {
                    printf("Packet too small for IP header\n");
                    rte_pktmbuf_free(mbuf);
                    continue;
                }
                
                struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(
                    mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
                
                // Modify packet
                ipv4_hdr->time_to_live++;
                
                // Determine destination
                uint16_t dst_port;
                if ((ipv4_hdr->dst_addr & subnet_mask) == internal_subnet.s_addr) {
                    dst_port = internal_port;
                } else {
                    dst_port = external_port;
                }
                
                // Send packet
                if (rte_eth_tx_burst(dst_port, 0, &mbuf, 1) == 0) {
                    rte_pktmbuf_free(mbuf);
                }
            }
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    printf("Starting application...\n");
    
    // Initialize EAL
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization, ret=%d\n", ret);
    }

    argc -= ret;
    argv += ret;

    printf("EAL initialized, parsing application arguments\n");
    parse_args(argc, argv);
    
    // For virtual devices, use a single queue setup
    nb_queues = 1;
    nb_workers = rte_lcore_count() - 1; // One worker per core, minus main core
    if (nb_workers == 0) {
        nb_workers = 1; // Ensure at least one worker
    }
    
    printf("Creating mbuf pool...\n");
    // Create mbuf pool with a larger cache size for virtual devices
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", 
                                       NB_MBUF * (nb_workers + 2), // Extra mbufs for virtual devices
                                       MBUF_CACHE_SIZE,
                                       0, 
                                       RTE_MBUF_DEFAULT_BUF_SIZE, 
                                       rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: %s\n", 
                 rte_strerror(rte_errno));
    }

    printf("Creating rx ring...\n");
    // Create RX ring
    rx_ring = rte_ring_create("RX_RING", RX_RING_SIZE, 
                             rte_socket_id(), 
                             RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (rx_ring == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create RX ring: %s\n", 
                 rte_strerror(rte_errno));
    }

    printf("Creating worker rings...\n");
    // Create worker rings
    worker_rings = rte_zmalloc("worker_rings", 
                              sizeof(struct rte_ring *) * nb_workers, 
                              RTE_CACHE_LINE_SIZE);
    if (worker_rings == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot allocate worker rings: %s\n", 
                 rte_strerror(rte_errno));
    }
    
    for (uint16_t i = 0; i < nb_workers; i++) {
        char name[32];
        snprintf(name, sizeof(name), "WORKER_RING_%u", i);
        worker_rings[i] = rte_ring_create(name, WORKER_RING_SIZE, 
                                         rte_socket_id(), 
                                         RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (worker_rings[i] == NULL) {
            rte_exit(EXIT_FAILURE, "Cannot create worker ring %u: %s\n", 
                     i, rte_strerror(rte_errno));
        }
    }

    printf("Initializing ports...\n");
    init_ports();

    printf("Launching worker threads...\n");
    // Launch worker threads
    unsigned lcore_id;
    uint16_t worker_id = 0;
    
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (worker_id < nb_workers) {
            printf("Launching worker %u on lcore %u\n", worker_id, lcore_id);
            rte_eal_remote_launch(worker, (void *)(uintptr_t)worker_id, lcore_id);
            worker_id++;
        }
    }

    printf("Launching RX thread on main core...\n");
    // Launch RX thread on main lcore
    rx_thread((void *)(uintptr_t)src_port);

    // Never reached - RX thread runs forever
    // But for completeness:
    
    // Wait for workers
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_wait_lcore(lcore_id);
    }

    // Cleanup
    rte_ring_free(rx_ring);
    for (uint16_t i = 0; i < nb_workers; i++) {
        rte_ring_free(worker_rings[i]);
    }
    rte_free(worker_rings);
    rte_mempool_free(mbuf_pool);

    return 0;
}