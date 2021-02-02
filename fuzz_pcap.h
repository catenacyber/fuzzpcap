// Copyright (c) 2021 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>

#include <stdint.h>
#include <stddef.h>

#define FPC0_HEADER_LEN 4
#define FPC0_HEADER "FPC0"

int FPC_IsFuzzPacketCapture(const uint8_t *Data, size_t Size);
