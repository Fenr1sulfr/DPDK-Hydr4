#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <stdatomic.h>
#include <rte_mempool.h>

/* Shared memory zone for statistics */
#define STATS_MEMZONE "statistics_memzone"

/* Application statistics structure */
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

/* Extern shared application statistics */
extern struct app_stats* stats;

/* Function declarations */
void print_stats(void);
void init_stats(void);
void update_stats(void);

#endif // STATS_H