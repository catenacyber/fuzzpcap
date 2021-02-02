// Copyright (c) 2021 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <pcap/pcap.h>

#include "fuzz_pcap.h"

int main(int argc, char** argv)
{
    struct stat filestat;
    uint8_t * mapped;
    pcap_t * pkts;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *pkt;
    struct pcap_pkthdr *header;
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
        //TODO output pcap file
        printf("Thanks for FPC\n");
    } else {
        printf("Trying pcap\n");
        pkts = pcap_open_offline(argv[1], errbuf);
        if (pkts == NULL) {
            fprintf(stderr, "Cannot open pcap file\n");
        } else {
            //TODO check return value
            fwrite(FPC0_HEADER, FPC0_HEADER_LEN, 1, stdout);
            while (pcap_next_ex(pkts, &header, &pkt) > 0) {
                //loop over packets
                //TODO define a fixed endianess
                fwrite(&header->ts.tv_sec, 8, 1, stdout);
                fwrite(&header->ts.tv_usec, 8, 1, stdout);
                //TODO escape FPC0_HEADER
                fwrite(pkt, 1, header->caplen, stdout);
                fwrite(FPC0_HEADER, FPC0_HEADER_LEN, 1, stdout);
            }
            pcap_close(pkts);
        }
    }

    munmap(mapped, filestat.st_size);
    close(fd);

    return 0;
}

