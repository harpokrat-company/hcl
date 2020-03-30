//
// Created by neodar on 30/03/2020.
//

#include "CryptoHelper.h"

template<uint8_t BytesNumber>
void HCL::Crypto::CryptoHelper::CopyBytes(const uint8_t word[BytesNumber], uint8_t destination[BytesNumber]) {
  for (uint8_t i = 0; i < BytesNumber; ++i) {
    destination[i] = word[i];
  }
}

template<uint8_t BytesNumber>
void HCL::Crypto::CryptoHelper::RotBytes(const uint8_t word[BytesNumber], uint8_t destination[BytesNumber]) {
  uint8_t temporary_byte = BytesNumber > 0 ? word[0] : 0;
  for (uint8_t i = 0; i < BytesNumber - 1; ++i) {
    destination[i] = word[(i + 1) % BytesNumber];
  }
  destination[BytesNumber - 1] = temporary_byte;
}

template<uint8_t BytesNumber>
void HCL::Crypto::CryptoHelper::XorBytes(const uint8_t a[BytesNumber],
                                                const uint8_t b[BytesNumber],
                                                uint8_t destination[BytesNumber]) {
  for (uint8_t i = 0; i < BytesNumber; ++i) {
    destination[i] = a[i] ^ b[i];
  }
}

void HCL::Crypto::CryptoHelper::CopyWord(const uint8_t word[4], uint8_t destination[4]) {
  CopyBytes<4>(word, destination);
}

void HCL::Crypto::CryptoHelper::RotWord(const uint8_t word[4], uint8_t destination[4]) {
  RotBytes<4>(word, destination);
}

void HCL::Crypto::CryptoHelper::XorWords(const uint8_t a[4], const uint8_t b[4], uint8_t destination[4]) {
  XorBytes<4>(a, b, destination);
}
