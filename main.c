/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

 #include <stdint.h>
 #include <stdlib.h>
 #include <inttypes.h>
 #include <rte_eal.h>
 #include <rte_ethdev.h>
 #include <rte_cycles.h>
 #include <rte_lcore.h>
 #include <rte_mbuf.h>
 #include <rte_ring.h>
 
 #define RX_RING_SIZE 1024
 #define TX_RING_SIZE 1024
 
 #define NUM_MBUFS 4096   /* Increased for more packet replication */
 #define MBUF_CACHE_SIZE 216  /* Increased cache size */
 #define BURST_SIZE 32
 
 /* Number of replicated packets per original packet */
 #define REPLICATION_FACTOR 100
 
 /* Ring sizes for inter-core communication */
 #define RING_SIZE 8192       /* Increased for more packet capacity */
 
 /* Rings for inter-core communication */
 static struct rte_ring *rx_to_worker;
 static struct rte_ring *worker_to_tx;
 
 /* basicfwd.c: DPDK multi-core forwarding example with packet replication. */
 
 /*
  * Initializes a given port using global settings and with the RX buffers
  * coming from the mbuf_pool passed as a parameter.
  */
 static inline int
 port_init(uint16_t port, struct rte_mempool *mbuf_pool)
 {
     struct rte_eth_conf port_conf;
     const uint16_t rx_rings = 1, tx_rings = 1;
     uint16_t nb_rxd = RX_RING_SIZE;
     uint16_t nb_txd = TX_RING_SIZE;
     int retval;
     uint16_t q;
     struct rte_eth_dev_info dev_info;
     struct rte_eth_txconf txconf;
 
     if (!rte_eth_dev_is_valid_port(port))
         return -1;
 
     memset(&port_conf, 0, sizeof(struct rte_eth_conf));
 
     retval = rte_eth_dev_info_get(port, &dev_info);
     if (retval != 0) {
         printf("Error during getting device (port %u) info: %s\n",
                 port, strerror(-retval));
         return retval;
     }
 
     if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
         port_conf.txmode.offloads |=
             RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
 
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
                 rte_eth_dev_socket_id(port), NULL, mbuf_pool);
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
 
 /* RX lcore: receives packets and places them in a ring buffer */
 static int
 lcore_rx(void *arg)
 {
     uint16_t port;
     struct rte_mbuf *bufs[BURST_SIZE];
     
     printf("\nRX Core %u receiving packets. [Ctrl+C to quit]\n", rte_lcore_id());
     
     /* Check for NUMA issues */
     RTE_ETH_FOREACH_DEV(port)
         if (rte_eth_dev_socket_id(port) >= 0 &&
                 rte_eth_dev_socket_id(port) != (int)rte_socket_id())
             printf("WARNING, port %u is on remote NUMA node to RX thread.\n\tPerformance will not be optimal.\n", port);
     
     /* Main work of RX core */
     for (;;) {
         RTE_ETH_FOREACH_DEV(port) {
             /* Get burst of RX packets */
             const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
             
             if (likely(nb_rx > 0)) {
                 /* Enqueue received packets to the ring for worker */
                 uint16_t nb_enqueued = rte_ring_enqueue_burst(rx_to_worker, 
                                                              (void **)bufs, 
                                                              nb_rx, 
                                                              NULL);
                 
                 /* Free any packets that couldn't be enqueued */
                 if (unlikely(nb_enqueued < nb_rx)) {
                     uint16_t buf;
                     for (buf = nb_enqueued; buf < nb_rx; buf++)
                         rte_pktmbuf_free(bufs[buf]);
                 }
                 
                 /* Print statistics - only when packets are received */
                 static uint64_t total_rx = 0;
                 total_rx += nb_rx;
                 if (total_rx % 1000 == 0) {
                     printf("RX Core: Received %"PRIu64" packets so far\n", total_rx);
                 }
             }
         }
     }
     
     return 0;
 }
 
 /* Worker lcore: modifies packets and replicates each packet 100 times */
 static int
 lcore_worker(void *arg)
 {
     struct rte_mbuf *bufs[BURST_SIZE];
     struct rte_mbuf *out_bufs[BURST_SIZE * REPLICATION_FACTOR];
     struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
     uint16_t i, j, r, nb_rx, nb_out;
     uint64_t total_replicated = 0;
     
     printf("\nWorker Core %u replicating packets 1:%d. [Ctrl+C to quit]\n", 
            rte_lcore_id(), REPLICATION_FACTOR);
     
     /* Main work of worker core */
     for (;;) {
         /* Dequeue packets from rx_to_worker ring */
         nb_rx = rte_ring_dequeue_burst(rx_to_worker, 
                                       (void **)bufs, 
                                       BURST_SIZE, 
                                       NULL);
         
         if (likely(nb_rx > 0)) {
             /* Process each packet - replicate 100 times */
             nb_out = 0;
             for (i = 0; i < nb_rx; i++) {
                 /* First packet is the original with some modification */
                 struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(bufs[i], 
                                                                struct rte_ether_hdr *);
                 
                 /* Simple modification: Swap source and destination MAC */
                 struct rte_ether_addr temp_addr;
                 rte_ether_addr_copy(&eth_hdr->dst_addr, &temp_addr);
                 rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
                 rte_ether_addr_copy(&temp_addr, &eth_hdr->src_addr);
                 
                 /* Add original packet to output */
                 out_bufs[nb_out++] = bufs[i];
                 
                 /* Create 99 replicated packets */
                 for (r = 1; r < REPLICATION_FACTOR; r++) {
                     struct rte_mbuf *copy = rte_pktmbuf_copy(bufs[i], mbuf_pool, 0, UINT32_MAX);
                     if (likely(copy != NULL)) {
                         /* Optional: Make unique modifications to each copy */
                         struct rte_ether_hdr *copy_eth_hdr = rte_pktmbuf_mtod(copy, 
                                                                           struct rte_ether_hdr *);
                         
                         /* As an example, slightly modify the last byte of the dest MAC 
                          * to differentiate the replicated packets */
                         copy_eth_hdr->dst_addr.addr_bytes[5] = (r & 0xFF);
                         
                         out_bufs[nb_out++] = copy;
                     }
                 }
                 
                 total_replicated += REPLICATION_FACTOR;
                 if (total_replicated % 10000 == 0) {
                     printf("Worker Core: Replicated %"PRIu64" packets so far\n", total_replicated);
                 }
             }
             
             /* We need to send the packets in smaller bursts since we have many of them */
             for (j = 0; j < nb_out; j += BURST_SIZE) {
                 uint16_t burst_size = RTE_MIN(BURST_SIZE, nb_out - j);
                 uint16_t nb_enqueued = rte_ring_enqueue_burst(worker_to_tx, 
                                                             (void **)&out_bufs[j], 
                                                             burst_size, 
                                                             NULL);
                 
                 /* Free any packets that couldn't be enqueued */
                 if (unlikely(nb_enqueued < burst_size)) {
                     uint16_t buf;
                     for (buf = j + nb_enqueued; buf < j + burst_size; buf++)
                         rte_pktmbuf_free(out_bufs[buf]);
                 }
             }
         }
     }
     
     return 0;
 }
 
 /* TX lcore: transmits packets */
 static int
 lcore_tx(void *arg)
 {
     uint16_t port;
     struct rte_mbuf *bufs[BURST_SIZE];
     uint16_t nb_tx, nb_rx;
     uint64_t total_tx = 0;
     
     printf("\nTX Core %u transmitting packets. [Ctrl+C to quit]\n", rte_lcore_id());
     
     /* Check for NUMA issues */
     RTE_ETH_FOREACH_DEV(port)
         if (rte_eth_dev_socket_id(port) >= 0 &&
                 rte_eth_dev_socket_id(port) != (int)rte_socket_id())
             printf("WARNING, port %u is on remote NUMA node to TX thread.\n\tPerformance will not be optimal.\n", port);
     
     /* Main work of TX core */
     for (;;) {
         /* Dequeue packets from worker_to_tx ring */
         nb_rx = rte_ring_dequeue_burst(worker_to_tx, 
                                       (void **)bufs, 
                                       BURST_SIZE, 
                                       NULL);
         
         if (likely(nb_rx > 0)) {
             /* Transmit packets to all available ports */
             RTE_ETH_FOREACH_DEV(port) {
                 /* Send burst of TX packets */
                 nb_tx = rte_eth_tx_burst(port, 0, bufs, nb_rx);
                 total_tx += nb_tx;
                 
                 /* Print statistics periodically */
                 if (total_tx % 10000 == 0) {
                     printf("TX Core: Transmitted %"PRIu64" packets so far\n", total_tx);
                 }
                 
                 /* Free any unsent packets */
                 if (unlikely(nb_tx < nb_rx)) {
                     uint16_t buf;
                     for (buf = nb_tx; buf < nb_rx; buf++)
                         rte_pktmbuf_free(bufs[buf]);
                 }
             }
         }
     }
     
     return 0;
 }
 
 /*
  * The main function, which does initialization and launches the per-lcore functions.
  */
 int
 main(int argc, char *argv[])
 {
     struct rte_mempool *mbuf_pool;
     unsigned nb_ports;
     uint16_t portid;
     int ret;
     unsigned lcore_id;
 
     /* Initialize the Environment Abstraction Layer (EAL). */
     ret = rte_eal_init(argc, argv);
     if (ret < 0)
         rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
 
     argc -= ret;
     argv += ret;
 
     /* Check that there are available ports */
     nb_ports = rte_eth_dev_count_avail();
     if (nb_ports == 0)
         rte_exit(EXIT_FAILURE, "Error: no ports available\n");
 
     /* Check that we have enough lcores for our 3-stage pipeline */
     if (rte_lcore_count() < 4) /* 3 workers + main */
         rte_exit(EXIT_FAILURE, "Error: need at least 4 lcores (3 workers + main)\n");
 
     /* Creates a larger mempool for the 100x replication */
     mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", 
                                         NUM_MBUFS * nb_ports * REPLICATION_FACTOR, 
                                         MBUF_CACHE_SIZE, 
                                         0, 
                                         RTE_MBUF_DEFAULT_BUF_SIZE, 
                                         rte_socket_id());
     if (mbuf_pool == NULL)
         rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
 
     /* Create rings for inter-core communication */
     rx_to_worker = rte_ring_create("rx_to_worker", RING_SIZE, 
                                   rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
     
     worker_to_tx = rte_ring_create("worker_to_tx", RING_SIZE, 
                                   rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
     
     if (rx_to_worker == NULL || worker_to_tx == NULL)
         rte_exit(EXIT_FAILURE, "Cannot create needed rings\n");
 
     /* Initialize all ports. */
     RTE_ETH_FOREACH_DEV(portid)
         if (port_init(portid, mbuf_pool) != 0)
             rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
 
     printf("Packet Replication Application:\n");
     printf("--------------------------------\n");
     printf("Each RX packet will be replicated %d times\n", REPLICATION_FACTOR);
     printf("--------------------------------\n");
 
     /* Launch worker functions on available lcores */
     lcore_id = rte_get_next_lcore(-1, 1, 0);
     rte_eal_remote_launch(lcore_rx, NULL, lcore_id);
     printf("Launched RX function on lcore %u\n", lcore_id);
     
     lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
     rte_eal_remote_launch(lcore_worker, mbuf_pool, lcore_id);
     printf("Launched worker function on lcore %u\n", lcore_id);
     
     lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
     rte_eal_remote_launch(lcore_tx, NULL, lcore_id);
     printf("Launched TX function on lcore %u\n", lcore_id);
 
     /* Main core does nothing but wait for workers to finish (which they won't) */
     rte_eal_mp_wait_lcore();
 
     /* Clean up the EAL */
     rte_eal_cleanup();
 
     return 0;
 }