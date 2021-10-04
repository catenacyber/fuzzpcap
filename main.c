// Copyright (c) 2021 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <pcap/pcap.h>

#include "fuzz_pcap.h"

int main(int argc, char** argv)
{
    struct stat filestat;
    uint8_t * mapped;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *pkt;
    int r;

    if (argc != 2) {
        fprintf(stderr, "Expect one argument\n");
        return 1;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Cannot open file\n");
        return 1;
    }
    if (fstat (fd, &filestat) < 0) {
        fprintf(stderr, "Cannot get size of file\n");
        close(fd);
        return 1;
    }
    mapped = mmap(0, filestat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        fprintf(stderr, "Cannot mmap file\n");
        close(fd);
        return 1;
    }

    if (FPC_IsFuzzPacketCapture(mapped, filestat.st_size)) {
        pcap_t *pd;
        pcap_dumper_t *pdumper;
        FPC_buffer_t pkts;
        struct pcap_pkthdr header;

        int r = FPC_init(&pkts, mapped, filestat.st_size);
        if (r >= 0) {
            pd = pcap_open_dead(pkts.datalink, FPC_SNAPLEN);
            pdumper = pcap_dump_fopen(pd, stdout);
            while (FPC_next(&pkts, &header, &pkt) > 0) {
                pcap_dump((u_char *) pdumper, &header, pkt);
            }
            pcap_close(pd);
            pcap_dump_close(pdumper);
        }
    } else {
        struct pcap_pkthdr *header;

        pcap_t * pkts = pcap_open_offline(argv[1], errbuf);
        if (pkts == NULL) {
            fprintf(stderr, "Cannot open pcap file\n");
        } else {
            uint8_t dl = FPC_datalink_from(pcap_datalink(pkts));
            if (dl != FPC_DATALINK_ERROR) {
                uint8_t bufts[FPC_TS_MAXSIZE];
                //TODO check return value
                fwrite(FPC0_MAGIC, FPC0_MAGIC_LEN-1, 1, stdout);
                fwrite(&dl, 1, 1, stdout);
                //loop over packets
                while (pcap_next_ex(pkts, &header, &pkt) > 0) {
                    //TODO define a fixed endianess
                    memset(bufts, 0, FPC_TS_MAXSIZE);
                    memcpy(bufts, &header->ts.tv_sec, sizeof(header->ts.tv_sec));
                    memcpy(bufts+FPC_TS_MAXSIZE/2, &header->ts.tv_usec, sizeof(header->ts.tv_usec));
                    fwrite(bufts, FPC_TS_MAXSIZE, 1, stdout);
                    fwrite(pkt, 1, header->caplen, stdout);
                    if (header->caplen > FPC_SNAPLEN) {
                        fprintf(stderr, "Warning packet too bug for snaplen\n");
                    }
                    //TODO escape FPC0_MAGIC
                    fwrite(FPC0_MAGIC, FPC0_MAGIC_LEN, 1, stdout);
                }
            } else {
                fprintf(stderr, "Cannot use pcap datalink\n");
            }
            pcap_close(pkts);
        }
    }

    munmap(mapped, filestat.st_size);
    close(fd);

    return 0;
}

