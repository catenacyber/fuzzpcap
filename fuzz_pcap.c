// Copyright (c) 2021 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <pcap/pcap.h>

#include "fuzz_pcap.h"

int FPC_IsFuzzPacketCapture(const uint8_t *Data, size_t Size) {
    if (Size < FPC0_HEADER_LEN) {
        return 0;
    }
    if (memcmp(Data, FPC0_HEADER, FPC0_HEADER_LEN - 1) != 0) {
        return 0;
    }
    if (FPC_datalink_to(Data[FPC0_HEADER_LEN-1]) == FPC_DATALINK_ERROR) {
        return 0;
    }
    return 1;
}

uint32_t FPC_datalink_to(uint8_t in) {
    if (in == DLT_NULL || in == DLT_EN10MB) {
        return in;
    }
    return (uint32_t) FPC_DATALINK_ERROR;
}

uint8_t FPC_datalink_from(uint32_t in) {
    if (in == DLT_NULL || in == DLT_EN10MB) {
        return in;
    }
    return FPC_DATALINK_ERROR;
}

int FPC_init(FPC_buffer_t *r, const uint8_t *Data, size_t Size) {
    if (!FPC_IsFuzzPacketCapture(Data, Size)) {
        return -1;
    }
    r->Data = Data;
    r->Size = Size;
    r->offset = FPC0_HEADER_LEN;
    r->datalink = FPC_datalink_to(Data[FPC0_HEADER_LEN-1]);
    return 0;
}

//TODO 1 tcp stream only
int FPC_next(FPC_buffer_t *pkts, struct pcap_pkthdr *header, const uint8_t **pkt) {
    if (pkts->offset >= pkts->Size) {
        return 0;
    }

    *pkt = pkts->Data + pkts->offset + sizeof(header->ts.tv_sec) + sizeof(header->ts.tv_usec);
    const uint8_t *next = memmem(pkts->Data + pkts->offset, pkts->Size - pkts->offset, FPC0_HEADER, FPC0_HEADER_LEN);
    if (next == NULL) {
        next = pkts->Data + pkts->Size;
    }
    if (next < *pkt) {
        //wrong input
        return -1;
    }

    memset(header, sizeof(struct pcap_pkthdr), 0);
    header->ts.tv_sec = *((time_t *) (pkts->Data + pkts->offset));
    header->ts.tv_usec = *((suseconds_t *) (pkts->Data + pkts->offset + sizeof(header->ts.tv_sec)));
    header->caplen = next - (*pkt);
    header->len = header->caplen;

    pkts->offset += header->caplen + sizeof(header->ts.tv_sec) + sizeof(header->ts.tv_usec) + FPC0_HEADER_LEN;
    return 1;
}
