// Copyright (c) 2021 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>

#include <stdint.h>
#include <stddef.h>

#define FPC0_HEADER_LEN 4
#define FPC0_HEADER "FPC0"

#define FPC_SNAPLEN 0xFFFF

#define FPC_DATALINK_ERROR 0xFF

typedef struct _FPC_buffer {
    const uint8_t *Data;
    size_t Size;
    size_t offset;
    uint32_t datalink;
} FPC_buffer_t;

int FPC_IsFuzzPacketCapture(const uint8_t *Data, size_t Size);

uint8_t FPC_datalink_from(uint32_t in);
uint32_t FPC_datalink_to(uint8_t in);

int FPC_init(FPC_buffer_t *r, const uint8_t *Data, size_t Size);

int FPC_next(FPC_buffer_t *pkts, struct pcap_pkthdr *header, const uint8_t **pkt);
