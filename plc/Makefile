# FrostyGoop District Heating Simulation
# Build configuration

CC = gcc
CFLAGS_COMMON = -Wall -Wextra -D_GNU_SOURCE
LDFLAGS = -L/usr/local/lib -lmodbus -lpthread -lm -Wl,-rpath,/usr/local/lib
INCLUDES = -I/usr/local/include/modbus

# Source files
SRCS = heating_controller.c process_sim.c display.c
HDRS = process_sim.h display.h
TARGET = heating_controller

# Release build
CFLAGS_RELEASE = $(CFLAGS_COMMON) -O2

# Debug build
CFLAGS_DEBUG = $(CFLAGS_COMMON) -g -O0 -DDEBUG

# ASAN build
CFLAGS_ASAN = $(CFLAGS_COMMON) -g -O1 -fsanitize=address -fno-omit-frame-pointer

.PHONY: all release debug asan clean

all: release

release: CFLAGS = $(CFLAGS_RELEASE)
release: $(TARGET)

debug: CFLAGS = $(CFLAGS_DEBUG)
debug: $(TARGET)

asan: CFLAGS = $(CFLAGS_ASAN)
asan: LDFLAGS += -fsanitize=address
asan: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o
