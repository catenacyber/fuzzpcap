// Copyright (c) 2021 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>

#include <stdint.h>
#include <stddef.h>

#include "fuzz_pcap.h"

int FPC_IsFuzzPacketCapture(const uint8_t *Data, size_t Size) {
    if (Size < FPC0_HEADER_LEN) {
        return 0;
    }
    for(size_t i = 0; i < FPC0_HEADER_LEN; i++) {
        if (Data[i] != FPC0_HEADER[i]) {
            return 0;
        }
    }
    return 1;
}
