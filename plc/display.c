/*
 * display.c - Console Display for District Heating Simulation
 *
 * Renders ASCII art visualization of the heating system
 */

#include "display.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ==========================================================================
 * Utility Functions
 * ========================================================================== */

void display_clear(void) {
    printf("\033[2J\033[H");
    fflush(stdout);
}

void format_runtime(uint32_t seconds, char *buffer, size_t size) {
    int hours = seconds / 3600;
    int mins = (seconds % 3600) / 60;
    int secs = seconds % 60;
    snprintf(buffer, size, "%02d:%02d:%02d", hours, mins, secs);
}

/* ==========================================================================
 * Temperature Bar Rendering
 * ========================================================================== */

static void render_temp_bar(double temp, double setpoint) {
    /* Bar spans -20 to 40°C (60 degree range) */
    const int bar_width = 50;
    const double temp_min = -20.0;
    const double temp_max = 40.0;

    /* Calculate positions */
    int temp_pos = (int)((temp - temp_min) / (temp_max - temp_min) * bar_width);
    int setpoint_pos = (int)((setpoint - temp_min) / (temp_max - temp_min) * bar_width);

    /* Clamp positions */
    if (temp_pos < 0) temp_pos = 0;
    if (temp_pos >= bar_width) temp_pos = bar_width - 1;
    if (setpoint_pos < 0) setpoint_pos = 0;
    if (setpoint_pos >= bar_width) setpoint_pos = bar_width - 1;

    /* Determine color based on status */
    const char *bar_color;
    if (temp <= TEMP_FROZEN) {
        bar_color = COLOR_RED;
    } else if (temp <= TEMP_CRITICAL) {
        bar_color = COLOR_RED;
    } else if (temp <= TEMP_WARNING) {
        bar_color = COLOR_YELLOW;
    } else {
        bar_color = COLOR_GREEN;
    }

    /* Render bar */
    printf("   │      │");
    for (int i = 0; i < bar_width; i++) {
        if (i == setpoint_pos) {
            printf("%s│%s", COLOR_CYAN, COLOR_RESET);
        } else if (i < temp_pos) {
            printf("%s█%s", bar_color, COLOR_RESET);
        } else {
            printf("░");
        }
    }
    printf("│          │\n");
}

/* ==========================================================================
 * Main Display Rendering
 * ========================================================================== */

void display_render(const process_state_t *state, int clients,
                    const char *ip, int port) {
    char runtime_str[16];
    format_runtime(state->runtime, runtime_str, sizeof(runtime_str));

    /* Determine status display */
    const char *status_str;
    const char *status_color;
    const char *status_icon;

    switch (state->status) {
        case STATUS_OK:
            status_str = "NORMAL";
            status_color = COLOR_GREEN;
            status_icon = "✓";
            break;
        case STATUS_WARNING:
            status_str = "WARNING";
            status_color = COLOR_YELLOW;
            status_icon = "⚠";
            break;
        case STATUS_CRITICAL:
            status_str = "CRITICAL";
            status_color = COLOR_RED;
            status_icon = "🚨";
            break;
        case STATUS_FROZEN:
        case STATUS_BURST:
            status_str = "FROZEN";
            status_color = COLOR_RED;
            status_icon = "💀";
            break;
        default:
            status_str = "UNKNOWN";
            status_color = COLOR_WHITE;
            status_icon = "?";
    }

    /* PLC status */
    const char *plc_status;
    const char *plc_color;
    if (state->controller_running) {
        plc_status = "RUNNING";
        plc_color = COLOR_GREEN;
    } else {
        plc_status = "CRASHED";
        plc_color = COLOR_RED;
    }

    /* Warning messages */
    const char *warning1 = "";
    const char *warning2 = "";
    if (!state->controller_running) {
        warning1 = "▶ CONTROLLER CRASHED - VALVE NOT RESPONDING";
        if (state->status == STATUS_WARNING) {
            warning2 = "▶ TEMPERATURE DROPPING - HYPOTHERMIA RISK";
        } else if (state->status == STATUS_CRITICAL) {
            warning2 = "▶ PIPE FREEZE IMMINENT - EVACUATE BUILDING";
        }
    }

    /* Clear and render */
    display_clear();

    printf("╔══════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║            DISTRICT HEATING CONTROLLER - BUILDING 47, ZONE 3                 ║\n");
    printf("║               FrostyGoop Target Simulation (libmodbus 3.1.2)                 ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║                                                                              ║\n");
    printf("║   OUTSIDE TEMP     ❄️   %6.1f°C                                              ║\n", state->outside_temp);
    printf("║                                                                              ║\n");
    printf("║   ┌────────────────────────────────────────────────────────────────────┐     ║\n");

    /* Building zone header with status indicators */
    if (state->status >= STATUS_WARNING) {
        printf("║   │  BUILDING ZONE                                        %s%s %s %s%s   │     ║\n",
               status_color, status_icon, status_icon, status_icon, COLOR_RESET);
    } else {
        printf("║   │  BUILDING ZONE                                                     │     ║\n");
    }

    printf("║   │                                                                    │     ║\n");
    printf("║   │              INSIDE TEMPERATURE                                    │     ║\n");
    printf("║   │      ┌──────────────────────────────────────────────────┐          │     ║\n");

    /* Temperature bar */
    printf("║");
    render_temp_bar(state->inside_temp, state->setpoint);
    printf("     ║\n");

    printf("║   │      └──────────────────────────────────────────────────┘          │     ║\n");
    printf("║   │      -20        0        10        20        30       40°C         │     ║\n");

    /* Current temperature display */
    if (state->status >= STATUS_CRITICAL) {
        printf("║   │                           %s%6.1f°C %s%s                              │     ║\n",
               COLOR_RED, state->inside_temp, status_icon, COLOR_RESET);
    } else if (state->status == STATUS_WARNING) {
        printf("║   │                           %s%6.1f°C %s%s                              │     ║\n",
               COLOR_YELLOW, state->inside_temp, status_icon, COLOR_RESET);
    } else {
        printf("║   │                           %s%6.1f°C%s  (Setpoint: %.1f°C)              │     ║\n",
               COLOR_GREEN, state->inside_temp, COLOR_RESET, state->setpoint);
    }

    printf("║   │                                                                    │     ║\n");

    /* Valve and radiator display */
    const char *valve_color = state->controller_running ? COLOR_GREEN : COLOR_RED;
    const char *valve_warning = state->controller_running ? "" : " ⚠";

    printf("║   │      ┌─────────┐     ┌──────────────┐                              │     ║\n");
    printf("║   │      │ ░░░░░░░ │ ◄── │ VALVE: %s%3d%%%s │ ◄── Supply %.0f°C%s           │     ║\n",
           valve_color, state->valve_actual, COLOR_RESET, state->supply_temp, valve_warning);

    /* Radiator state based on temperature */
    if (state->inside_temp <= TEMP_CRITICAL) {
        printf("║   │      │   ICE   │     └──────────────┘                              │     ║\n");
        printf("║   │      │ FORMING │                                                   │     ║\n");
    } else if (state->valve_actual > 50) {
        printf("║   │      │ ▓▓▓▓▓▓▓ │     └──────────────┘                              │     ║\n");
        printf("║   │      │  (HOT)  │                                                   │     ║\n");
    } else if (state->valve_actual > 0) {
        printf("║   │      │ ░░░░░░░ │     └──────────────┘                              │     ║\n");
        printf("║   │      │ (WARM)  │                                                   │     ║\n");
    } else {
        printf("║   │      │         │     └──────────────┘                              │     ║\n");
        printf("║   │      │ (COLD)  │                                                   │     ║\n");
    }

    printf("║   │      └─────────┘     Power: %5.1f kW                               │     ║\n", state->heater_power);
    printf("║   │                                                                    │     ║\n");
    printf("║   └────────────────────────────────────────────────────────────────────┘     ║\n");
    printf("║                                                                              ║\n");

    /* Mode and status line */
    printf("║   MODE: [%s%s%s]     STATUS: %s%s %s%s     RUNTIME: %s               ║\n",
           state->mode == MODE_AUTO ? COLOR_GREEN : COLOR_YELLOW,
           state->mode == MODE_AUTO ? "AUTO  " : "MANUAL",
           COLOR_RESET,
           status_color, status_icon, status_str, COLOR_RESET,
           runtime_str);

    printf("║                                                                              ║\n");

    /* Warning messages */
    if (strlen(warning1) > 0) {
        printf("║   %s%-70s%s   ║\n", COLOR_RED, warning1, COLOR_RESET);
    }
    if (strlen(warning2) > 0) {
        printf("║   %s%-70s%s   ║\n", COLOR_RED, warning2, COLOR_RESET);
    }
    if (strlen(warning1) > 0 || strlen(warning2) > 0) {
        printf("║                                                                              ║\n");
    }

    printf("╠══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║  Modbus TCP: %s:%-5d | Clients: %d | PLC: %s%-7s%s                       ║\n",
           ip, port, clients, plc_color, plc_status, COLOR_RESET);
    printf("╚══════════════════════════════════════════════════════════════════════════════╝\n");

    fflush(stdout);
}

/* ==========================================================================
 * Failure Screen
 * ========================================================================== */

void display_render_failure(const process_state_t *state) {
    char runtime_str[16];
    format_runtime(state->time_without_control, runtime_str, sizeof(runtime_str));

    display_clear();

    printf("╔══════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║            DISTRICT HEATING CONTROLLER - BUILDING 47, ZONE 3                 ║\n");
    printf("║               FrostyGoop Target Simulation (libmodbus 3.1.2)                 ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║                                                                              ║\n");
    printf("║                                                                              ║\n");
    printf("║                     %s██████████████████████████████████%s                       ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                   %s██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██%s                     ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░                                ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░    ❄️  PIPES FROZEN / BURST  ❄️   ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░                                ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░    Final Temperature: %5.1f°C   ░░██%s                   ║\n", COLOR_BG_RED, state->inside_temp, COLOR_RESET);
    printf("║                 %s██░░    Time without heat: %s  ░░██%s                   ║\n", COLOR_BG_RED, runtime_str, COLOR_RESET);
    printf("║                 %s██░░                                ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░    BUILDING DAMAGE:            ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░    • Burst pipes               ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░    • Water flooding            ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░    • Structure damage          ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░                                ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                   %s██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██%s                     ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                     %s██████████████████████████████████%s                       ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                                                                              ║\n");
    printf("║   %sROOT CAUSE:%s Controller crash via CVE-2019-14462 exploit                   ║\n", COLOR_YELLOW, COLOR_RESET);
    printf("║   %sATTACK VECTOR:%s FrostyGoop-style malformed Modbus TCP packet               ║\n", COLOR_YELLOW, COLOR_RESET);
    printf("║                                                                              ║\n");
    printf("║   %s💀 CATASTROPHIC FAILURE - SIMULATION HALTED 💀%s                             ║\n", COLOR_RED, COLOR_RESET);
    printf("║                                                                              ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║  Restart with: docker-compose restart plc                                    ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════╝\n");

    fflush(stdout);
}
