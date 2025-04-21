/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

 #include <stdint.h>
 #include <stdlib.h>
 #include <stdatomic.h>
 #include <inttypes.h>
 #include <string.h>
 #include <stdio.h>
 #include <signal.h>
 #include <rte_eal.h>
 #include <rte_ethdev.h>
 #include <rte_cycles.h>
 #include <rte_lcore.h>
 #include <rte_mbuf.h>
 #include <rte_ring.h>
 #include <rte_malloc.h>
 #include <rte_timer.h>
 #include <rte_prefetch.h>
 #include <rte_branch_prediction.h>
 #include <rte_mempool.h>
 
 /* Constants for port and ring configuration */
 #define RX_RING_SIZE     4096 //4096
 #define TX_RING_SIZE     4096  //4096
 #define NUM_MBUFS        (8192)   /* Significantly increased for 100 Gbps (8192*32)*/ 
 #define MBUF_CACHE_SIZE  512 //512
 #define BURST_SIZE       64       //64   /* Increased for higher throughput */
 #define MAX_RX_BURST     32        //32  /* Keep RX burst reasonable */
 #define PREFETCH_OFFSET  4        //4   /* Prefetch 4 packets ahead */
 
 /* Number of replicated packets per original packet */
 #define REPLICATION_FACTOR 250
 
 /* Ring sizes for inter-core communication */
 #define RING_SIZE        32768    //32768   /* Significantly increased */
 
 /* Number of descriptors to allocate for each queue */
 #define NB_RXD           4096 //4096
 #define NB_TXD           4096 //4096
 
 /* Number of rings between cores */
 #define NUM_RX_WORKER_RINGS  4     //4
 #define NUM_WORKER_TX_RINGS  8 //8
 
 /* Shared memory zone for statistics */
 #define STATS_MEMZONE "statistics_memzone"
 
 /* Application statistics */
 struct app_stats {
    atomic_uint_fast64_t rx_packets;
    atomic_uint_fast64_t tx_packets;
    atomic_uint_fast64_t dropped_packets;
    atomic_uint_fast64_t worker_packets;
    atomic_uint_fast64_t rx_processing_time_us;
    atomic_uint_fast64_t worker_processing_time_us;
    atomic_uint_fast64_t tx_processing_time_us;
    uint64_t last_tsc;
     float rx_pps;
     float tx_pps;
     atomic_uint_fast8_t stop_program;
 };
 
 /* Shared application statistics */
 static struct app_stats* stats;
 
 /* Rings for inter-core communication */
 static struct rte_ring *rx_to_worker_rings[NUM_RX_WORKER_RINGS];
 static struct rte_ring *worker_to_tx_rings[NUM_WORKER_TX_RINGS];
 static char ring_names[32][32];
 
 /* Memory pools */
 static struct rte_mempool *rx_mbuf_pool;
 static struct rte_mempool *tx_mbuf_pool;
 
 /* Signal handler for graceful shutdown */
 static void signal_handler(int signum)
 {
     if (signum == SIGINT || signum == SIGTERM) {
         printf("\nSignal %d received, preparing to exit...\n", signum);
         stats->stop_program = 1;
     }
 }
 
 /* Display statistics every second */
static void print_stats(void)
{      
    const uint64_t total_rx = atomic_load(&stats->rx_packets);
    const uint64_t total_tx = atomic_load(&stats->tx_packets);
    const uint64_t total_dropped = atomic_load(&stats->dropped_packets);
    const uint64_t total_worker = atomic_load(&stats->worker_packets);
    const uint64_t rx_pps = atomic_load(&stats->rx_pps);
    const uint64_t tx_pps = atomic_load(&stats->tx_pps);
    
    printf("\033[2J\033[H"); /* Clear screen */
    printf("============================ Statistics ============================\n");
    printf("Packets received: %"PRIu64" (%llu Mpps)\n", 
          total_rx, (unsigned long long)(rx_pps/1000000));
    printf("Packets processed by workers: %"PRIu64"\n", total_worker);
    printf("Packets transmitted: %"PRIu64" (%llu Mpps)\n", 
          total_tx, (unsigned long long)(tx_pps/1000000));
    printf("Packets dropped: %"PRIu64"\n", total_dropped);
    printf("Processing times (microseconds):\n");
    printf("  RX: %"PRIu64" | Worker: %"PRIu64" | TX: %"PRIu64"\n",
          atomic_load(&stats->rx_processing_time_us),
          atomic_load(&stats->worker_processing_time_us),
          atomic_load(&stats->tx_processing_time_us));
    printf("====================================================================\n");
     
    /* Calculate throughput - use actual tx_pps (not in millions) */
    if (tx_pps > 0) {
        /* Assuming 1500 bytes per packet for estimation */
        double throughput_gbps = (tx_pps * 1500 * 8) / 1000000000.0;
        printf("Estimated throughput: %.2f Gbps\n", throughput_gbps);
    }
    printf("====================================================================\n");
}
 
 /* Initialize statistics collection */
 static void init_stats(void)
 {
     const struct rte_memzone *mz;
     
     mz = rte_memzone_reserve(STATS_MEMZONE, sizeof(struct app_stats),
                              rte_socket_id(), 0);
     if (mz == NULL)
         rte_exit(EXIT_FAILURE, "Cannot reserve memory zone for statistics\n");
     
     stats = mz->addr;
     memset(stats, 0, sizeof(struct app_stats));
    atomic_store(&stats->last_tsc, rte_rdtsc());
 }
 
 /* Update statistics */
static void update_stats(void)
{
    static uint64_t prev_rx = 0, prev_tx = 0;
    static uint64_t timer_tsc = 0;
    uint64_t cur_tsc = rte_rdtsc();
    
    /* Initialize timer on first call */
    if (timer_tsc == 0)
        timer_tsc = cur_tsc;
    
    /* Update stats approximately once per second */
    if (cur_tsc - timer_tsc > rte_get_timer_hz()) {
        uint64_t rx_diff = atomic_load(&stats->rx_packets) - prev_rx;
        uint64_t tx_diff = atomic_load(&stats->tx_packets) - prev_tx;
        float time_diff_sec = (float)(cur_tsc - timer_tsc) / rte_get_timer_hz();
        
        /* Calculate packets per second (not in millions) */
        atomic_store(&stats->rx_pps, rx_diff/time_diff_sec);
        atomic_store(&stats->tx_pps, tx_diff/time_diff_sec);
        
        prev_rx = atomic_load(&stats->rx_packets);
        prev_tx = atomic_load(&stats->tx_packets);
        timer_tsc = cur_tsc;
        
        print_stats();
    }
}
 
 /*
  * Initializes a given port using global settings and with the RX buffers
  * coming from the mbuf_pool passed as a parameter.
  */
 static inline int
 port_init(uint16_t port)
 {
     struct rte_eth_conf port_conf = {
         .rxmode = {
             .mq_mode = RTE_ETH_MQ_RX_RSS,
            //  .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
            //  .split_hdr_size = 0,
         },
         .rx_adv_conf = {
             .rss_conf = {
                 .rss_key = NULL,
                 .rss_hf = 0,
                //  .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP,
             },
         },
         .txmode = {
             .mq_mode = RTE_ETH_MQ_TX_NONE,
            //  .offloads = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE,
         },
     };
     
     const uint16_t rx_rings = 1, tx_rings = 1;
     uint16_t nb_rxd = NB_RXD;
     uint16_t nb_txd = NB_TXD;
     int retval;
     uint16_t q;
     struct rte_eth_dev_info dev_info;
     struct rte_eth_txconf txconf;
     
     if (!rte_eth_dev_is_valid_port(port))
         return -1;
     
     retval = rte_eth_dev_info_get(port, &dev_info);
     if (retval != 0) {
         printf("Error during getting device (port %u) info: %s\n",
                 port, strerror(-retval));
         return retval;
     }
     
     if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
         port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
     
     /* Configure the Ethernet device. */
     retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
     if (retval != 0)
         return retval;
     
     retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
     if (retval != 0)
         return retval;
     
     /* Allocate and set up 1 RX queue per Ethernet port. */
     for (q = 0; q < rx_rings; q++) {
         retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                 rte_eth_dev_socket_id(port), NULL, rx_mbuf_pool);
         if (retval < 0)
             return retval;
     }
     
     txconf = dev_info.default_txconf;
     txconf.offloads = port_conf.txmode.offloads;
     /* Allocate and set up 1 TX queue per Ethernet port. */
     for (q = 0; q < tx_rings; q++) {
         retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                 rte_eth_dev_socket_id(port), &txconf);
         if (retval < 0)
             return retval;
     }
     
     /* Starting Ethernet port. */
     retval = rte_eth_dev_start(port);
     if (retval < 0)
         return retval;
     
     /* Display the port MAC address. */
     struct rte_ether_addr addr;
     retval = rte_eth_macaddr_get(port, &addr);
     if (retval != 0)
         return retval;
     
     printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
             port, RTE_ETHER_ADDR_BYTES(&addr));
     
     /* Enable RX in promiscuous mode for the Ethernet device. */
     retval = rte_eth_promiscuous_enable(port);
     if (retval != 0)
         return retval;
     
     return 0;
 }
 
 /* RX lcore: receives packets and distributes them to worker rings */
 static int
 lcore_rx(void *arg)
 {
     uint16_t port = *(uint16_t*)arg;
     uint32_t num_workers = rte_lcore_count() - 3; /* Exclude main, RX, TX */
     struct rte_mbuf *bufs[MAX_RX_BURST];
     uint16_t nb_rx, i, ring_idx = 0;
     uint64_t start_tsc, end_tsc, diff_tsc;
     
     printf("\nRX Core %u receiving packets on port %u. [Ctrl+C to quit]\n", 
            rte_lcore_id(), port);
     
     /* Check for NUMA issues */
     if (rte_eth_dev_socket_id(port) >= 0 &&
             rte_eth_dev_socket_id(port) != (int)rte_socket_id())
         printf("WARNING: Port %u is on remote NUMA node to RX thread.\n"
                "\tPerformance will not be optimal.\n", port);
     
     /* Main work of RX core */
     while (!atomic_load(&stats->stop_program)) {
         start_tsc = rte_rdtsc();
         
         /* Get burst of RX packets */
         nb_rx = rte_eth_rx_burst(port, 0, bufs, MAX_RX_BURST);
         
         if (likely(nb_rx > 0)) {
             /* Prefetch first packets */
             for (i = 0; i < PREFETCH_OFFSET && i < nb_rx; i++) {
                 rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
             }
             
             /* Process packet burst */
             for (i = 0; i < nb_rx; i++) {
                 /* Prefetch next packets */
                 if (i + PREFETCH_OFFSET < nb_rx)
                     rte_prefetch0(rte_pktmbuf_mtod(bufs[i + PREFETCH_OFFSET], void *));
                 
                 /* Distribute packets in round-robin to worker rings */
                 uint16_t worker = ring_idx % NUM_RX_WORKER_RINGS;
                 ring_idx++;
                 
                 /* Enqueue packet to the selected worker ring */
                 if (rte_ring_enqueue(rx_to_worker_rings[worker], bufs[i]) != 0) {
                     /* Ring full - drop the packet */
                     rte_pktmbuf_free(bufs[i]);
                     atomic_store(&stats->dropped_packets,atomic_load(&stats->dropped_packets) + 1);
                 }
             }
             
             /* Update statistics */
             atomic_store(&stats->rx_packets,atomic_load(&stats->rx_packets) + nb_rx);
           
         }
         
         end_tsc = rte_rdtsc();
         diff_tsc = end_tsc - start_tsc;
         atomic_store(&stats->rx_processing_time_us, diff_tsc * 1000000 / rte_get_timer_hz());
         update_stats();
     }
     
     return 0;
 }
 
 /* Worker lcore: dequeues packets, modifies them, and creates replicas */
 static int
 lcore_worker(void *arg)
 {
     uint32_t worker_id = *(uint32_t*)arg;
     uint32_t ring_idx = worker_id % NUM_RX_WORKER_RINGS;
     uint32_t output_ring_idx = worker_id % NUM_WORKER_TX_RINGS;
     struct rte_mbuf *buf, *copies[REPLICATION_FACTOR];
     struct rte_mbuf *out_bufs[BURST_SIZE];
     uint16_t nb_out = 0, i, j, nb_tx;
     uint64_t start_tsc, end_tsc, diff_tsc;
     
     printf("\nWorker Core %u (worker_id=%u) using rx_ring=%u, tx_ring=%u\n", 
            rte_lcore_id(), worker_id, ring_idx, output_ring_idx);
     
     /* Main work of worker core */
     while (!stats->stop_program) {
         start_tsc = rte_rdtsc();
         
         /* Get a packet from the rx ring */
         if (rte_ring_dequeue(rx_to_worker_rings[ring_idx], (void **)&buf) == 0) {
             /* We got a packet - process it */
             int replicated = 0;
             
             /* Basic packet modification - swap MAC addresses */
            //  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
            //  struct rte_ether_addr temp_addr;
            //  rte_ether_addr_copy(&eth_hdr->dst_addr, &temp_addr);
            //  rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
            //  rte_ether_addr_copy(&temp_addr, &eth_hdr->src_addr);
             
             /* Create replicated packets efficiently */
             copies[0] = buf;  /* First "copy" is the original */
             replicated = 1;
             
             /* Batch allocate the other copies */
             for (i = 1; i < REPLICATION_FACTOR; i++) {
                 copies[i] = rte_pktmbuf_copy(buf, tx_mbuf_pool, 0, UINT32_MAX);
                 if (likely(copies[i] != NULL)) {
                     replicated++;
                     
                     /* Optionally modify each replica slightly */
                     struct rte_ether_hdr *copy_eth_hdr = rte_pktmbuf_mtod(copies[i], 
                                                                      struct rte_ether_hdr *);
                     copy_eth_hdr->dst_addr.addr_bytes[5] = i & 0xFF; /* Unique last byte */
                 }
             }
             
             /* Send packets to TX ring in smaller bursts */
             for (j = 0; j < replicated; j++) {
                 out_bufs[nb_out++] = copies[j];
                 
                 /* When we have enough packets for a burst, send them */
                 if (nb_out == BURST_SIZE) {
                     nb_tx = 0;
                     while (nb_tx < nb_out && !stats->stop_program) {
                         nb_tx += rte_ring_enqueue_burst(
                             worker_to_tx_rings[output_ring_idx],
                             (void **)(out_bufs + nb_tx),
                             nb_out - nb_tx, NULL);
                     }
                     nb_out = 0;
                 }
             }
             
             /* Update worker stats */
             atomic_store(&stats->worker_packets, 
                          atomic_load(&stats->worker_packets) + replicated);
         }
         
         /* Flush any remaining packets */
         if (nb_out > 0) {
             nb_tx = 0;
             while (nb_tx < nb_out && !stats->stop_program) {
                 nb_tx += rte_ring_enqueue_burst(
                     worker_to_tx_rings[output_ring_idx],
                     (void **)(out_bufs + nb_tx),
                     nb_out - nb_tx, NULL);
             }
             nb_out = 0;
         }
         
         end_tsc = rte_rdtsc();
         diff_tsc = end_tsc - start_tsc;
         atomic_store(&stats->worker_processing_time_us, 
                     diff_tsc * 1000000 / rte_get_timer_hz());
     }
     
     return 0;
 }
 
 /* TX lcore: transmits packets */
 static int
 lcore_tx(void *arg)
 {
     uint16_t port = *(uint16_t*)arg;
     struct rte_mbuf *bufs[BURST_SIZE];
     uint16_t nb_rx, nb_tx, i;
     uint64_t start_tsc, end_tsc, diff_tsc;
     uint32_t ring_idx = 0;
     
     printf("\nTX Core %u transmitting packets on port %u. [Ctrl+C to quit]\n", 
            rte_lcore_id(), port);
     
     /* Check for NUMA issues */
     if (rte_eth_dev_socket_id(port) >= 0 &&
             rte_eth_dev_socket_id(port) != (int)rte_socket_id())
         printf("WARNING: Port %u is on remote NUMA node to TX thread.\n"
                "\tPerformance will not be optimal.\n", port);
     
     /* Main work of TX core */
     while (!atomic_load(&stats->stop_program)) {
         start_tsc = rte_rdtsc();
         uint16_t total_sent = 0;
         
         /* Poll all worker-to-TX rings in round robin */
         for (ring_idx = 0; ring_idx < NUM_WORKER_TX_RINGS && !atomic_load(&stats->stop_program); ring_idx++) {
             /* Dequeue packets from worker_to_tx ring */
             nb_rx = rte_ring_dequeue_burst(worker_to_tx_rings[ring_idx], 
                                           (void **)bufs, 
                                           BURST_SIZE, 
                                           NULL);
             
             if (likely(nb_rx > 0)) {
                 /* Prefetch first packets */
                 for (i = 0; i < PREFETCH_OFFSET && i < nb_rx; i++) {
                     rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
                 }
                 
                 /* Send burst of TX packets */
                 nb_tx = rte_eth_tx_burst(port, 0, bufs, nb_rx);
                 total_sent += nb_tx;
                 
                 /* Update statistics */
                 stats->tx_packets += nb_tx;
                 
                 /* Free any unsent packets */
                 if (unlikely(nb_tx < nb_rx)) {
                     for (i = nb_tx; i < nb_rx; i++) {
                         rte_pktmbuf_free(bufs[i]);
                         atomic_store(&stats->dropped_packets, 
                                         atomic_load(&stats->dropped_packets) + 1);
                     }
                 }
             }
         }
         
         end_tsc = rte_rdtsc();
         diff_tsc = end_tsc - start_tsc;
         atomic_store(&stats->tx_packets, 
                     atomic_load(&stats->tx_packets) + total_sent);
         update_stats();
     }
     
     return 0;
 }
 
 /*
  * The main function, which does initialization and launches the per-lcore functions.
  */
 int
 main(int argc, char *argv[])
 {
     unsigned int nb_ports;
     uint16_t portid;
     unsigned lcore_id;
     uint32_t worker_id = 0;
     uint16_t port_ids[RTE_MAX_ETHPORTS];
     uint32_t worker_ids[RTE_MAX_LCORE];
     int ret;
     char mempool_name[32];
     
     /* Initialize the Environment Abstraction Layer (EAL). */
     ret = rte_eal_init(argc, argv);
     if (ret < 0)
         rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
     
     argc -= ret;
     argv += ret;
     
     /* Set up signal handlers */
     signal(SIGINT, signal_handler);
     signal(SIGTERM, signal_handler);
     
     /* Initialize statistics */
     init_stats();
     
     /* Check that there are available ports */
     nb_ports = rte_eth_dev_count_avail();
     if (nb_ports == 0)
         rte_exit(EXIT_FAILURE, "Error: no ports available\n");
     
     printf("Found %u ports\n", nb_ports);
     
     /* Check that we have enough lcores for our application */
     unsigned int required_lcores = 1 + 1 + 1 + NUM_RX_WORKER_RINGS; /* main + rx + tx + workers */
     if (rte_lcore_count() < required_lcores)
         rte_exit(EXIT_FAILURE, "Error: not enough lcores (need at least %u)\n", required_lcores);
     
     /* Create separate mempools for RX and TX for better performance */
     snprintf(mempool_name, sizeof(mempool_name), "RX_MBUF_POOL");
     rx_mbuf_pool = rte_pktmbuf_pool_create(mempool_name, 
                                          NUM_MBUFS, 
                                          MBUF_CACHE_SIZE, 
                                          0, 
                                          RTE_MBUF_DEFAULT_BUF_SIZE, 
                                          rte_socket_id());
     if (rx_mbuf_pool == NULL)
         rte_exit(EXIT_FAILURE, "Cannot create RX mbuf pool\n");
     
     snprintf(mempool_name, sizeof(mempool_name), "TX_MBUF_POOL");
     tx_mbuf_pool = rte_pktmbuf_pool_create(mempool_name, 
                                          NUM_MBUFS * REPLICATION_FACTOR, 
                                          MBUF_CACHE_SIZE, 
                                          0, 
                                          RTE_MBUF_DEFAULT_BUF_SIZE, 
                                          rte_socket_id());
     if (tx_mbuf_pool == NULL)
         rte_exit(EXIT_FAILURE, "Cannot create TX mbuf pool\n");
     
     /* Create rings for inter-core communication */
     for (int i = 0; i < NUM_RX_WORKER_RINGS; i++) {
         snprintf(ring_names[i], sizeof(ring_names[0]), "rx_to_worker_%d", i);
         rx_to_worker_rings[i] = rte_ring_create(ring_names[i], RING_SIZE, 
                                               rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
         if (rx_to_worker_rings[i] == NULL)
             rte_exit(EXIT_FAILURE, "Cannot create rx_to_worker ring %d\n", i);
     }
     
     for (int i = 0; i < NUM_WORKER_TX_RINGS; i++) {
         snprintf(ring_names[NUM_RX_WORKER_RINGS + i], sizeof(ring_names[0]), "worker_to_tx_%d", i);
         worker_to_tx_rings[i] = rte_ring_create(ring_names[NUM_RX_WORKER_RINGS + i], RING_SIZE, 
                                               rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
         if (worker_to_tx_rings[i] == NULL)
             rte_exit(EXIT_FAILURE, "Cannot create worker_to_tx ring %d\n", i);
     }
     
     /* Use the first port available */
     portid = 0;
     while (portid < RTE_MAX_ETHPORTS && 
            rte_eth_dev_is_valid_port(portid) && 
            port_init(portid) == 0) {
         port_ids[portid] = portid;
         portid++;
     }
     
     if (portid == 0)
         rte_exit(EXIT_FAILURE, "All ports were not initialized\n");
     
     printf("Initialized %u ports\n", portid);
     
     /* Reset portid for launching workers */
     portid = 0;
     
     printf("\n================ 1:100 Packet Replication Application ================\n");
     printf("Each RX packet will be replicated %d times\n", REPLICATION_FACTOR);
     printf("Using %d RX-to-Worker rings and %d Worker-to-TX rings\n", 
            NUM_RX_WORKER_RINGS, NUM_WORKER_TX_RINGS);
     printf("===================================================================\n\n");
     
     /* Launch worker functions on available lcores */
     
     /* Launch RX core */
     lcore_id = rte_get_next_lcore(-1, 1, 0);
     if (lcore_id == RTE_MAX_LCORE)
         rte_exit(EXIT_FAILURE, "Not enough cores for RX\n");
     printf("Launching RX function on lcore %u\n", lcore_id);
     rte_eal_remote_launch(lcore_rx, &port_ids[portid], lcore_id);
     
     /* Launch worker cores */
     for (int i = 0; i < NUM_RX_WORKER_RINGS; i++) {
         worker_ids[worker_id] = worker_id;
         lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
         if (lcore_id == RTE_MAX_LCORE)
             rte_exit(EXIT_FAILURE, "Not enough cores for worker %d\n", worker_id);
         printf("Launching worker %u function on lcore %u\n", worker_id, lcore_id);
         rte_eal_remote_launch(lcore_worker, &worker_ids[worker_id], lcore_id);
         worker_id++;
     }
     
     /* Launch TX core */
     lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
     if (lcore_id == RTE_MAX_LCORE)
         rte_exit(EXIT_FAILURE, "Not enough cores for TX\n");
     printf("Launching TX function on lcore %u\n", lcore_id);
     rte_eal_remote_launch(lcore_tx, &port_ids[portid], lcore_id);
     
     /* Main core just handles stats and checking for program termination */
     while (!atomic_load(&stats->stop_program)) {
         update_stats();
         rte_delay_ms(500);
     }
     
     printf("\nWaiting for all cores to exit...\n");
     rte_eal_mp_wait_lcore();
     
     /* Clean up ports */
     RTE_ETH_FOREACH_DEV(portid) {
         if (rte_eth_dev_is_valid_port(portid)) {
             printf("Closing port %u\n", portid);
             rte_eth_dev_stop(portid);
             rte_eth_dev_close(portid);
         }
     }
     
     printf("\nApplication terminated\n");
     
     /* Clean up the EAL */
     rte_eal_cleanup();
     
     return 0;
 }