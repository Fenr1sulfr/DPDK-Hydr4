
#include <stdint.h>
 #include <stdlib.h>
 #include <stdatomic.h>
 #include <inttypes.h>
 #include <string.h>
 #include <stdio.h>
 #include <rte_mempool.h>


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
struct app_stats* stats;


/* Display statistics every second */
void print_stats(void)
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
 void init_stats(void)
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
void update_stats(void)
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