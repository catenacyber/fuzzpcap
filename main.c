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

#include "fuzz_pcap.h"

int main(int argc, char** argv)
{
    struct stat filestat;
    uint8_t * mapped;

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
        //TODO read pcap file
        printf("Trying pcap\n");
    }

    munmap(mapped, filestat.st_size);
    close(fd);

    return 0;
}

