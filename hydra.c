#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512
#define BURST_SIZE 32

static struct rte_mempool *mbuf_pool;

static inline void
forward(uint16_t rx_port, uint16_t tx_port) {
    struct rte_mbuf *bufs[BURST_SIZE];
    const uint16_t nb_rx = rte_eth_rx_burst(rx_port, 0, bufs, BURST_SIZE);
    if (nb_rx > 0)
        rte_eth_tx_burst(tx_port, 0, bufs, nb_rx);
}

static int
lcore_main(__rte_unused void *arg) {
    for (;;)
        forward(0, 1);
    return 0;
}

static void
init_port(uint16_t port) {
    struct rte_eth_conf conf = {0};
    struct rte_eth_dev_info info;
    struct rte_eth_txconf txconf;
    rte_eth_dev_info_get(port, &info);
    rte_eth_dev_configure(port, 1, 1, &conf);
    rte_eth_dev_adjust_nb_rx_tx_desc(port, &(uint16_t){RX_RING_SIZE}, &(uint16_t){TX_RING_SIZE});
    rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    txconf = info.default_txconf;
    txconf.offloads = conf.txmode.offloads;
    rte_eth_tx_queue_setup(port, 0, TX_RING_SIZE, rte_eth_dev_socket_id(port), &txconf);
    rte_eth_dev_start(port);
    rte_eth_promiscuous_enable(port);
}

int
main(int argc, char **argv) {
    if (rte_eal_init(argc, argv) < 0)
        return -1;

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", 4096, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    init_port(0);
    init_port(1);
    rte_eal_mp_remote_launch(lcore_main, NULL, CALL_MAIN);
    return 0;
}