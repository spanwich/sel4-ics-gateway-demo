/*
 * heating_controller.c - FrostyGoop District Heating Simulation
 *
 * Main program integrating:
 * - Process simulation (thermal model)
 * - Modbus TCP server (vulnerable libmodbus 3.1.2)
 * - Console display
 *
 * Demonstrates CVE-2019-14462 impact on industrial heating systems
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>
#include <modbus.h>

#include "process_sim.h"
#include "display.h"

/* ==========================================================================
 * Configuration
 * ========================================================================== */

#define SERVER_ADDRESS      "0.0.0.0"
#define SERVER_PORT         502
#define NB_REGISTERS        10
#define MAX_CONNECTIONS     64

#define LOG_FILE_ENV        "LOG_FILE"
#define DEFAULT_LOG_FILE    "/logs/plc.log"

/* ==========================================================================
 * Global State
 * ========================================================================== */

static volatile sig_atomic_t g_running = 1;
static process_state_t g_process;
static modbus_t *g_modbus_ctx = NULL;
static modbus_mapping_t *g_mb_mapping = NULL;
static FILE *g_log_fp = NULL;
static int g_client_count = 0;
static pthread_mutex_t g_client_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ==========================================================================
 * Logging
 * ========================================================================== */

static void log_msg(const char *level, const char *format, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[32];
    va_list args;

    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    if (g_log_fp) {
        va_start(args, format);
        fprintf(g_log_fp, "[%s] %s: ", timestamp, level);
        vfprintf(g_log_fp, format, args);
        fprintf(g_log_fp, "\n");
        fflush(g_log_fp);
        va_end(args);
    }
}

/* ==========================================================================
 * Signal Handler
 * ========================================================================== */

static void signal_handler(int signum) {
    log_msg("INFO", "Received signal %d, shutting down...", signum);
    g_running = 0;
}

/* ==========================================================================
 * Process Thread - Physics simulation and display
 * ========================================================================== */

static void *process_thread(void *arg) {
    (void)arg;

    while (g_running) {
        /* Update physics */
        process_update_physics(&g_process);

        /* Run controller if alive */
        if (g_process.controller_running) {
            process_run_controller(&g_process);
        }

        /* Copy to Modbus registers */
        process_to_registers(&g_process, g_mb_mapping->tab_registers);

        /* Update display */
        pthread_mutex_lock(&g_client_mutex);
        int clients = g_client_count;
        pthread_mutex_unlock(&g_client_mutex);

        if (g_process.pipes_burst) {
            display_render_failure(&g_process);
        } else {
            display_render(&g_process, clients, SERVER_ADDRESS, SERVER_PORT);
        }

        /* Sleep for update interval */
        usleep(UPDATE_INTERVAL_MS * 1000);
    }

    return NULL;
}

/* ==========================================================================
 * Modbus Handler - Processes client requests
 * ========================================================================== */

static void handle_modbus_client(modbus_t *ctx) {
    uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];
    int rc;

    while (g_running && g_process.controller_running) {
        rc = modbus_receive(ctx, query);

        if (rc > 0) {
            log_msg("INFO", "Received Modbus request: %d bytes", rc);

            /*
             * VULNERABILITY: CVE-2019-14462
             *
             * modbus_reply() trusts the Length field in the MBAP header.
             * If attacker sends:
             *   - Length field = 60 (small)
             *   - Actual data = 601 bytes (large)
             *
             * A heap buffer overflow occurs, crashing the server.
             */
            rc = modbus_reply(ctx, query, rc, g_mb_mapping);

            if (rc == -1) {
                log_msg("ERROR", "modbus_reply failed: %s", modbus_strerror(errno));
                break;
            }

            /* Check if client wrote to registers */
            process_from_registers(&g_process, g_mb_mapping->tab_registers);

            log_msg("INFO", "Sent Modbus reply: %d bytes", rc);

        } else if (rc == -1) {
            /* Connection closed or error */
            break;
        }
    }
}

/* ==========================================================================
 * Main Program
 * ========================================================================== */

int main(void) {
    int server_socket = -1;
    pthread_t process_tid;
    int rc;

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Open log file */
    const char *log_path = getenv(LOG_FILE_ENV);
    if (!log_path) log_path = DEFAULT_LOG_FILE;

    g_log_fp = fopen(log_path, "a");
    if (!g_log_fp) {
        fprintf(stderr, "Warning: Could not open log file %s\n", log_path);
    }

    log_msg("INFO", "========================================");
    log_msg("INFO", "FrostyGoop District Heating Simulation");
    log_msg("INFO", "libmodbus 3.1.2 (CVE-2019-14462)");
    log_msg("INFO", "WARNING: This is intentionally vulnerable!");
    log_msg("INFO", "========================================");

    /* Initialize process simulation */
    process_init(&g_process);
    log_msg("INFO", "Process simulation initialized");
    log_msg("INFO", "  Inside temp: %.1f°C", g_process.inside_temp);
    log_msg("INFO", "  Outside temp: %.1f°C", g_process.outside_temp);
    log_msg("INFO", "  Setpoint: %.1f°C", g_process.setpoint);

    /* Create Modbus TCP context */
    g_modbus_ctx = modbus_new_tcp(SERVER_ADDRESS, SERVER_PORT);
    if (!g_modbus_ctx) {
        log_msg("ERROR", "Failed to create Modbus context: %s", modbus_strerror(errno));
        goto cleanup;
    }

    /* Create register mapping */
    g_mb_mapping = modbus_mapping_new(0, 0, NB_REGISTERS, 0);
    if (!g_mb_mapping) {
        log_msg("ERROR", "Failed to allocate register mapping: %s", modbus_strerror(errno));
        goto cleanup;
    }

    /* Initialize registers from process state */
    process_to_registers(&g_process, g_mb_mapping->tab_registers);

    /* Start listening */
    server_socket = modbus_tcp_listen(g_modbus_ctx, MAX_CONNECTIONS);
    if (server_socket == -1) {
        log_msg("ERROR", "Failed to listen: %s", modbus_strerror(errno));
        goto cleanup;
    }

    log_msg("INFO", "Modbus TCP server listening on %s:%d", SERVER_ADDRESS, SERVER_PORT);

    /* Start process simulation thread */
    rc = pthread_create(&process_tid, NULL, process_thread, NULL);
    if (rc != 0) {
        log_msg("ERROR", "Failed to create process thread: %d", rc);
        goto cleanup;
    }

    /* Main loop - accept and handle Modbus clients */
    while (g_running) {
        log_msg("INFO", "Waiting for client connection...");

        rc = modbus_tcp_accept(g_modbus_ctx, &server_socket);
        if (rc == -1) {
            if (g_running) {
                log_msg("ERROR", "Accept failed: %s", modbus_strerror(errno));
            }
            continue;
        }

        pthread_mutex_lock(&g_client_mutex);
        g_client_count++;
        pthread_mutex_unlock(&g_client_mutex);

        log_msg("INFO", "Client connected");

        /* Handle this client */
        handle_modbus_client(g_modbus_ctx);

        pthread_mutex_lock(&g_client_mutex);
        g_client_count--;
        pthread_mutex_unlock(&g_client_mutex);

        log_msg("INFO", "Client disconnected");

        /* Check if we crashed (CVE triggered) */
        if (!g_process.controller_running) {
            log_msg("ERROR", "Controller crashed! Valve frozen at %d%%",
                    g_process.valve_actual);
            process_controller_crash(&g_process);
        }

        modbus_close(g_modbus_ctx);
    }

    /* Wait for process thread */
    pthread_join(process_tid, NULL);

cleanup:
    log_msg("INFO", "Shutting down...");

    if (g_mb_mapping) {
        modbus_mapping_free(g_mb_mapping);
    }
    if (g_modbus_ctx) {
        modbus_close(g_modbus_ctx);
        modbus_free(g_modbus_ctx);
    }
    if (server_socket != -1) {
        close(server_socket);
    }

    process_cleanup(&g_process);

    if (g_log_fp && g_log_fp != stdout) {
        fclose(g_log_fp);
    }

    return EXIT_SUCCESS;
}
