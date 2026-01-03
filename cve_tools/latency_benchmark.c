/*
 * Gateway Latency Benchmark Tool
 *
 * Measures round-trip latency through different gateway paths to compare
 * performance overhead of protocol-break vs packet-forwarding architectures.
 *
 * Compile: gcc -o latency_benchmark latency_benchmark.c -lm
 * Usage:   ./latency_benchmark <IP> <PORT> [iterations]
 *
 * For defensive security research only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <math.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define DEFAULT_ITERATIONS 100

/* Valid Modbus Read Holding Registers request */
static const uint8_t MODBUS_REQUEST[] = {
    /* MBAP Header */
    0x00, 0x01,  /* Transaction ID */
    0x00, 0x00,  /* Protocol ID */
    0x00, 0x06,  /* Length */
    0x01,        /* Unit ID */
    /* PDU */
    0x03,        /* Function: Read Holding Registers */
    0x00, 0x00,  /* Start address */
    0x00, 0x01   /* Quantity (1 register) */
};

typedef struct {
    double min;
    double max;
    double sum;
    double sum_sq;
    int count;
    int errors;
} Stats;

static double get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static int do_modbus_request(const char *ip, int port, double *latency_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    /* Set timeouts */
    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Disable Nagle */
    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)
    };
    inet_pton(AF_INET, ip, &addr.sin_addr);

    /* Measure connection + request/response */
    double start = get_time_ms();

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    if (send(sock, MODBUS_REQUEST, sizeof(MODBUS_REQUEST), 0) < 0) {
        close(sock);
        return -1;
    }

    uint8_t response[256];
    ssize_t received = recv(sock, response, sizeof(response), 0);

    double end = get_time_ms();
    close(sock);

    if (received < 0) return -1;

    *latency_ms = end - start;
    return 0;
}

static void update_stats(Stats *s, double value) {
    if (s->count == 0 || value < s->min) s->min = value;
    if (s->count == 0 || value > s->max) s->max = value;
    s->sum += value;
    s->sum_sq += value * value;
    s->count++;
}

static double stats_mean(Stats *s) {
    return s->count > 0 ? s->sum / s->count : 0;
}

static double stats_stddev(Stats *s) {
    if (s->count < 2) return 0;
    double mean = stats_mean(s);
    double variance = (s->sum_sq / s->count) - (mean * mean);
    return sqrt(variance > 0 ? variance : 0);
}

static void print_stats(const char *name, Stats *s) {
    printf("│ %-20s │ %8.2f │ %8.2f │ %8.2f │ %8.2f │ %4d/%4d │\n",
           name,
           s->min,
           stats_mean(s),
           s->max,
           stats_stddev(s),
           s->count,
           s->count + s->errors);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Gateway Latency Benchmark\n\n");
        printf("Usage: %s <IP> <PORT> [iterations]\n\n", argv[0]);
        printf("Measures round-trip latency for Modbus requests.\n\n");
        printf("Examples:\n");
        printf("  %s 127.0.0.1 502 100   # Benchmark seL4 gateway\n", argv[0]);
        printf("  %s 127.0.0.1 503 100   # Benchmark Snort gateway\n", argv[0]);
        printf("  %s 127.0.0.1 5020 100  # Benchmark direct PLC\n", argv[0]);
        return 1;
    }

    const char *ip = argv[1];
    int port = atoi(argv[2]);
    int iterations = (argc > 3) ? atoi(argv[3]) : DEFAULT_ITERATIONS;

    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Gateway Latency Benchmark                                     ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Target: %s:%d\n", ip, port);
    printf("Iterations: %d\n", iterations);
    printf("\n");

    Stats stats = {0};

    printf("Running benchmark");
    fflush(stdout);

    for (int i = 0; i < iterations; i++) {
        double latency;
        if (do_modbus_request(ip, port, &latency) == 0) {
            update_stats(&stats, latency);
        } else {
            stats.errors++;
        }

        if ((i + 1) % 10 == 0) {
            printf(".");
            fflush(stdout);
        }

        /* Small delay between requests */
        usleep(10000);  /* 10ms */
    }
    printf(" done!\n\n");

    printf("┌──────────────────────┬──────────┬──────────┬──────────┬──────────┬───────────┐\n");
    printf("│ Endpoint             │ Min (ms) │ Avg (ms) │ Max (ms) │ StdDev   │ Success   │\n");
    printf("├──────────────────────┼──────────┼──────────┼──────────┼──────────┼───────────┤\n");

    char name[32];
    snprintf(name, sizeof(name), "%s:%d", ip, port);
    print_stats(name, &stats);

    printf("└──────────────────────┴──────────┴──────────┴──────────┴──────────┴───────────┘\n");
    printf("\n");

    if (stats.errors > 0) {
        printf("Warning: %d requests failed (%.1f%% error rate)\n",
               stats.errors, 100.0 * stats.errors / iterations);
    }

    printf("\n");
    printf("Note: Protocol-break gateways (seL4) have higher latency due to:\n");
    printf("  • TCP connection termination and re-establishment\n");
    printf("  • Complete Modbus PDU validation before forwarding\n");
    printf("  • Two independent TCP connections (client→gateway, gateway→PLC)\n");
    printf("\n");
    printf("This latency overhead provides security benefits:\n");
    printf("  • Attacker cannot manipulate PLC's TCP state\n");
    printf("  • Complete request validation before any data reaches PLC\n");
    printf("  • Immune to TCP segmentation evasion attacks\n");
    printf("\n");

    return 0;
}
