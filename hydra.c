#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <signal.h>
#include <stdbool.h>

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512
#define BURST_SIZE 32

uint32_t num_packets = 2048;
static volatile bool keep_running = true;

static struct rte_mempool *mbuf_pool;

static void signal_handler(int signum) {
    keep_running = false;
}

static void handle_packet(struct rte_mbuf* pkt) {
    if (pkt == NULL) {
        fprintf(stderr, "Null packet received\n");
        return;
    }

    if (rte_pktmbuf_data_len(pkt) < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)) {
        fprintf(stderr, "Packet too short for headers\n");
        return;
    }

    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

    if (ip_hdr->next_proto_id == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)((unsigned char *)ip_hdr + (ip_hdr->ihl * 4));
        printf("TCP src port: %u, dst port: %u\n", rte_be_to_cpu_16(tcp_hdr->src_port),
               rte_be_to_cpu_16(tcp_hdr->dst_port));
    } else if (ip_hdr->next_proto_id == IPPROTO_UDP) {
        struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ip_hdr + (ip_hdr->ihl * 4));
        printf("UDP src port: %u, dst port: %u\n", rte_be_to_cpu_16(udp_hdr->src_port),
               rte_be_to_cpu_16(udp_hdr->dst_port));
    }
}

static inline void forward(uint16_t rx_port, uint16_t tx_port) {
    struct rte_mbuf *bufs[BURST_SIZE];
    const uint16_t nb_rx = rte_eth_rx_burst(rx_port, 0, bufs, BURST_SIZE);

    if (nb_rx == 0) {
        return; // No packets received
    }

    for (int i = 0; i < nb_rx; i++) {
        if (bufs[i] != NULL) {
            handle_packet(bufs[i]);
            rte_pktmbuf_free(bufs[i]); // Free the packet
        } else {
            fprintf(stderr, "Received null buffer at index %d\n", i);
        }
    }

    rte_eth_tx_burst(tx_port, 0, bufs, nb_rx);
}

static void init_port(uint16_t port) {
    struct rte_eth_conf conf = {0};
    struct rte_eth_dev_info info;
    struct rte_eth_txconf txconf;

    if (rte_eth_dev_info_get(port, &info) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to get device info for port %u\n", port);
    }

    if (rte_eth_dev_configure(port, 1, 1, &conf) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to configure port %u\n", port);
    }

    rte_eth_dev_adjust_nb_rx_tx_desc(port, &(uint16_t){RX_RING_SIZE}, &(uint16_t){TX_RING_SIZE});
    rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    txconf = info.default_txconf;
    txconf.offloads = conf.txmode.offloads;
    rte_eth_tx_queue_setup(port, 0, TX_RING_SIZE, rte_eth_dev_socket_id(port), &txconf);
    rte_eth_dev_start(port);
    rte_eth_promiscuous_enable(port);
}

int main(int argc, char **argv) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (rte_eal_init(argc, argv) < 0) {
        return -1;
    }

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", 4096, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }

    init_port(0);
    init_port(1);

    while (keep_running) {
        forward(0, 1);
    }

    rte_eth_dev_stop(0);
    rte_eth_dev_stop(1);
    rte_eth_dev_close(0);
    rte_eth_dev_close(1);
    rte_mempool_free(mbuf_pool);
    return 0;
}