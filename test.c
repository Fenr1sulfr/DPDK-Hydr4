


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


static struct rte_mempool *mbuf_pool;

static inline int
 port_init(uint16_t port)
 {
     struct rte_eth_conf port_conf = {
         .rxmode = {
             .mq_mode = RTE_ETH_MQ_RX_RSS,
         },
         .rx_adv_conf = {
             .rss_conf = {
                 .rss_key = NULL,
                 .rss_hf = 0,
             },
         },
         .txmode = {
             .mq_mode = RTE_ETH_MQ_TX_NONE,
         },
     };
     
     const uint16_t rx_rings = 1, tx_rings = 1;  // Multiple TX queues for TX cores
     uint16_t nb_rxd = 8192;
     uint16_t nb_txd = 8192;
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
     
     /* Allocate and set up RX queue */
     for (q = 0; q < rx_rings; q++) {
         retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                 rte_eth_dev_socket_id(port), NULL, mbuf_pool);
         if (retval < 0)
             return retval;
     }
     
     txconf = dev_info.default_txconf;
     txconf.offloads = port_conf.txmode.offloads;
     
     /* Allocate and set up multiple TX queues */
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
