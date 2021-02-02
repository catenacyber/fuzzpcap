// Copyright (c) 2021 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>

#include <stdint.h>
#include <stddef.h>

#define FPC0_HEADER_LEN 4

int FPC_IsFuzzPacketCapture(const uint8_t *Data, size_t Size) {
    if (Size < FPC0_HEADER_LEN) {
        return 0;
    }
    if (Data[0] != 'F' || Data[1] != 'P' || Data[2] != 'C' || Data[3] != '0') {
        return 0;
    }
    return 1;
}
