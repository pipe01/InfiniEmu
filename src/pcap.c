#include "pcap.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "ie_time.h"

typedef struct pcap_hdr_s
{
    uint32_t magic_number;  /* magic number */
    uint16_t version_major; /* major version number */
    uint16_t version_minor; /* minor version number */
    int32_t thiszone;       /* GMT to local correction */
    uint32_t sigfigs;       /* accuracy of timestamps */
    uint32_t snaplen;       /* max length of captured packets, in octets */
    uint32_t network;       /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s
{
    uint32_t ts_sec;   /* timestamp seconds */
    uint32_t ts_usec;  /* timestamp microseconds */
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
} pcaprec_hdr_t;

#define LINKTYPE_BLUETOOTH_LE_LL 251

struct pcap_t
{
    int fd;
    time_t start;
};

pcap_t *pcap_create(const char *path)
{
    pcap_t *pcap = malloc(sizeof(pcap_t));

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_DSYNC | O_RSYNC, 0644);
    if (fd < 0)
    {
        perror("open");
        exit(1);
    }

    pcap->fd = fd;

    pcap_hdr_t hdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = LINKTYPE_BLUETOOTH_LE_LL,
    };
    (void)!write(fd, &hdr, sizeof(hdr));

    return pcap;
}

void pcap_destroy(pcap_t *pcap)
{
    close(pcap->fd);
    free(pcap);
}

void pcap_write_packet(pcap_t *pcap, const uint8_t *data, size_t length)
{
    pcaprec_hdr_t hdr = {
        .ts_sec = pcap->start,
        .ts_usec = microseconds_now(),
        .incl_len = length,
        .orig_len = length,
    };

    (void)!write(pcap->fd, &hdr, sizeof(hdr));
    (void)!write(pcap->fd, data, length);
    fsync(pcap->fd);
}
