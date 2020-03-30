//
// Created by neodar on 28/03/2020.
//

#include "RijndaelKeySchedule.h"

const uint8_t HCL::Crypto::RijndaelKeySchedule::round_constants_[11] =
    {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
