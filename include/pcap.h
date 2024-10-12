#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct pcap_t pcap_t;

pcap_t *pcap_create(const char *path);
void pcap_destroy(pcap_t *);

void pcap_write_packet(pcap_t *, const uint8_t *data, size_t length);
