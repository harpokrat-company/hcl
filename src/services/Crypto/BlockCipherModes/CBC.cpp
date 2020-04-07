//
// Created by neodar on 06/04/2020.
//

#include "CBC.h"

HCL::Crypto::CBC::CBC(const std::string &header, size_t &header_length) :
    ABlockCipherMode(header, header_length),
    APaddedCipher(header, header_length),
    AInitializationVectorBlockCipherMode(header, header_length) {
}
