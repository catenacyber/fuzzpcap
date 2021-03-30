// Copyright (c) 2021 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <pcap/pcap.h>

#include "fuzz_pcap.h"

int FPC_IsFuzzPacketCapture(const uint8_t *Data, size_t Size) {
    if (Size < FPC0_HEADER_LEN) {
        return 0;
    }
    if (memcmp(Data, FPC0_MAGIC, FPC0_MAGIC_LEN - 1) != 0) {
        return 0;
    }
    if (FPC_datalink_to(Data[FPC0_MAGIC_LEN-1] & 0x7F) == FPC_DATALINK_ERROR) {
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
    r->datalink = FPC_datalink_to(Data[FPC0_MAGIC_LEN-1] & 0x7F);
    r->tcpSingleStream = (Data[FPC0_MAGIC_LEN-1] & 0x80);
    if (r->tcpSingleStream) {
        r->offset = FPC0_HEADER_LEN;
    } else {
        r->offset = FPC0_MAGIC_LEN;
    }
    memset(r->pkt, 0, FPC_SNAPLEN);
    r->tcpState = FPC_TCP_STATE_START;
    r->seqCliAckSrv = 0x10000000;
    r->seqSrvAckCli = 0x20000000;
    r->nb = 0;
    return 0;
}

#define FPC_TCP_FLAG_SYN 0x02
#define FPC_TCP_FLAG_ACK 0x10
#define FPC_TCP_FLAGS_NEG_OFFSET 7

#define FPC_NULL_HEADER "\x02\x00\x00\x00"
#define FPC_NULL_HEADER_LEN 4

#define FPC_ETH_HEADER "\x00\x01\x02\x03\x04\x05\x00\x01\x02\x03\x04\x05\x08\x00"
#define FPC_ETH_HEADER_LEN 14

#define FPC_IP4_HEADER "\x45\x00\xff\xff\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01" \
"\x7f\x00\x00\x01"
#define FPC_IP4_HEADER_LEN 20

#define FPC_TCP_HEADER_END "\xFF\xFF\x00\x00\x00\x00"
#define FPC_TCP_HEADER_END_LEN 6

static bpf_u_int32 buildTCPpacket(FPC_buffer_t *pkts, bool s2c, size_t plen) {
    bpf_u_int32 r = 0;
    if (pkts->datalink == DLT_NULL) {
        memcpy(pkts->pkt, FPC_NULL_HEADER, FPC_NULL_HEADER_LEN);
        r = FPC_NULL_HEADER_LEN;
    } else if (pkts->datalink == DLT_EN10MB) {
        memcpy(pkts->pkt, FPC_ETH_HEADER, FPC_ETH_HEADER_LEN);
        r = FPC_ETH_HEADER_LEN;
    } else {
        //unreachable
        abort();
    }
    memcpy(pkts->pkt+r, FPC_IP4_HEADER, FPC_IP4_HEADER_LEN);
    pkts->pkt[r+2] = (plen + FPC_IP4_HEADER_LEN + 20) >> 8;
    pkts->pkt[r+3] = (plen + FPC_IP4_HEADER_LEN+ 20);
    r += FPC_IP4_HEADER_LEN;
    //ports
    if (s2c) {
        memcpy(pkts->pkt+r, pkts->Data+FPC0_MAGIC_LEN, 2);
        memcpy(pkts->pkt+r+2, pkts->Data+FPC0_MAGIC_LEN+2, 2);
        pkts->pkt[r+4] = pkts->seqSrvAckCli >> 24;
        pkts->pkt[r+5] = pkts->seqSrvAckCli >> 16;
        pkts->pkt[r+6] = pkts->seqSrvAckCli >> 8;
        pkts->pkt[r+7] = pkts->seqSrvAckCli;
        pkts->pkt[r+8] = pkts->seqCliAckSrv >> 24;
        pkts->pkt[r+9] = pkts->seqCliAckSrv >> 16;
        pkts->pkt[r+10] = pkts->seqCliAckSrv >> 8;
        pkts->pkt[r+11] = pkts->seqCliAckSrv;
    } else {
        memcpy(pkts->pkt+r, pkts->Data+FPC0_MAGIC_LEN+2, 2);
        memcpy(pkts->pkt+r+2, pkts->Data+FPC0_MAGIC_LEN, 2);
        pkts->pkt[r+4] = pkts->seqCliAckSrv >> 24;
        pkts->pkt[r+5] = pkts->seqCliAckSrv >> 16;
        pkts->pkt[r+6] = pkts->seqCliAckSrv >> 8;
        pkts->pkt[r+7] = pkts->seqCliAckSrv;
        pkts->pkt[r+8] = pkts->seqSrvAckCli >> 24;
        pkts->pkt[r+9] = pkts->seqSrvAckCli >> 16;
        pkts->pkt[r+10] = pkts->seqSrvAckCli >> 8;
        pkts->pkt[r+11] = pkts->seqSrvAckCli;
    }
    r += 12;
    pkts->pkt[r] = 0x50; // TCP length
    pkts->pkt[r+1] = 0; // flags
    r+=2;
    memcpy(pkts->pkt+r, FPC_TCP_HEADER_END, FPC_TCP_HEADER_END_LEN);
    r+=FPC_TCP_HEADER_END_LEN;
    return r;
}

#define FCP_BASE_TIME 0x601cf51a
#define FPC_TS_MAXSIZE 16

int FPC_next_pcap(FPC_buffer_t *pkts, struct pcap_pkthdr *header, const uint8_t **pkt) {
    *pkt = pkts->Data + pkts->offset + FPC_TS_MAXSIZE;
    const uint8_t *next = memmem(pkts->Data + pkts->offset, pkts->Size - pkts->offset, FPC0_MAGIC, FPC0_MAGIC_LEN);
    if (next == NULL) {
        next = pkts->Data + pkts->Size;
    }
    if (next < *pkt) {
        //wrong input
        return -1;
    }

    memset(header, 0, sizeof(struct pcap_pkthdr));
    header->ts.tv_sec = *((time_t *) (pkts->Data + pkts->offset));
    if (header->ts.tv_sec < 0) {
        header->ts.tv_sec = -header->ts.tv_sec;
    }
    header->ts.tv_usec = *((suseconds_t *) (pkts->Data + pkts->offset + FPC_TS_MAXSIZE/2));
    header->caplen = next - (*pkt);
    pkts->offset += header->caplen + FPC_TS_MAXSIZE + FPC0_MAGIC_LEN;
    header->len = header->caplen;
    return 1;
}

int FPC_next_tcp(FPC_buffer_t *pkts, struct pcap_pkthdr *header, const uint8_t **pkt) {
    *pkt = pkts->Data + pkts->offset;
    const uint8_t *next = memmem(pkts->Data + pkts->offset, pkts->Size - pkts->offset, FPC0_MAGIC, FPC0_MAGIC_LEN);
    if (next == NULL) {
        next = pkts->Data + pkts->Size;
    }
    if (next < *pkt) {
        //wrong input
        return -1;
    }

    memset(header, 0, sizeof(struct pcap_pkthdr));
    header->ts.tv_sec = FCP_BASE_TIME;
    header->ts.tv_usec = pkts->nb;
    pkts->nb++;
    header->caplen = next - (*pkt);

    if (pkts->tcpState > FPC_TCP_STATE_SYNACK) {
        pkts->offset += header->caplen + FPC0_MAGIC_LEN;
    }
    switch (pkts->tcpState) {
        case FPC_TCP_STATE_START:
        pkts->tcpState = FPC_TCP_STATE_SYN;
        header->caplen = buildTCPpacket(pkts, false, 0);
        *pkt = pkts->pkt;
        pkts->pkt[header->caplen-FPC_TCP_FLAGS_NEG_OFFSET] |= FPC_TCP_FLAG_SYN;
        pkts->seqCliAckSrv++;
        break;

        case FPC_TCP_STATE_SYN:
        pkts->tcpState = FPC_TCP_STATE_SYNACK;
        header->caplen = buildTCPpacket(pkts, true, 0);
        *pkt = pkts->pkt;
        pkts->pkt[header->caplen-FPC_TCP_FLAGS_NEG_OFFSET] |= FPC_TCP_FLAG_SYN | FPC_TCP_FLAG_ACK;
        pkts->seqSrvAckCli++;
        break;

        case FPC_TCP_STATE_SYNACK:
        pkts->tcpState = FPC_TCP_STATE_ESTABLISHED;
        header->caplen = buildTCPpacket(pkts, false, 0);
        *pkt = pkts->pkt;
        pkts->pkt[header->caplen-FPC_TCP_FLAGS_NEG_OFFSET] |= FPC_TCP_FLAG_ACK;
        break;

        case FPC_TCP_STATE_ESTABLISHED:
        if (header->caplen < 2) {
            return -1;
        }
        header->caplen--;
        bool s2c = (*pkt[0]) & 1;
        header->len = buildTCPpacket(pkts, s2c, header->caplen);
        if (header->caplen + header->len > FPC_SNAPLEN) {
            header->caplen = FPC_SNAPLEN - header->len;
        }
        memcpy(pkts->pkt+header->len, *pkt+1, header->caplen);
        if (s2c) {
            pkts->seqSrvAckCli += header->caplen;
        } else {
            pkts->seqCliAckSrv += header->caplen;
        }
        header->caplen += header->len;
        *pkt = pkts->pkt;
        break;
    }
    header->len = header->caplen;
    return 1;
}

int FPC_next(FPC_buffer_t *pkts, struct pcap_pkthdr *header, const uint8_t **pkt) {
    if (pkts->offset >= pkts->Size) {
        return 0;
    }

    if (pkts->tcpSingleStream) {
        return FPC_next_tcp(pkts, header, pkt);
    } //else
    return FPC_next_pcap(pkts, header, pkt);
}
