//
// Created by neodar on 28/03/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_RIJNDAELKEYSCHEDULE_H_
#define HCL_SRC_SERVICES_CRYPTO_RIJNDAELKEYSCHEDULE_H_

#include <cstdint>

#include "RijndaelSubstitutionBox.h"

#define WORD_AT(variable, at)         (variable[(at) / 4] + ((at) % 4) * 4)

namespace HCL::Crypto {

class RijndaelKeySchedule {
 public:
  template<uint8_t KeySize, uint8_t RoundKeys>
  static void KeyExpansion(const uint8_t [KeySize], uint8_t [RoundKeys][16]);
  static void AES128KeyExpansion(const uint8_t (&key)[16], uint8_t (&round_keys)[11][16]) {
    KeyExpansion<16, 11>(key, round_keys);
  }
  static void AES192KeyExpansion(const uint8_t (&key)[24], uint8_t (&round_keys)[13][16]) {
    KeyExpansion<24, 13>(key, round_keys);
  }
  static void AES256KeyExpansion(const uint8_t (&key)[32], uint8_t (&round_keys)[15][16]) {
    KeyExpansion<32, 15>(key, round_keys);
  }
 private:
  template<uint8_t BytesNumber>
  static void CopyBytes(const uint8_t [BytesNumber], uint8_t [BytesNumber]);
  template<uint8_t BytesNumber>
  static void RotBytes(const uint8_t [BytesNumber], uint8_t [BytesNumber]);
  template<uint8_t BytesNumber>
  static void XorBytes(const uint8_t [BytesNumber], const uint8_t [BytesNumber], uint8_t [BytesNumber]);
  static void CopyWord(const uint8_t word[4], uint8_t destination[4]) {
    CopyBytes<4>(word, destination);
  }
  static void RotWord(const uint8_t word[4], uint8_t destination[4]) {
    RotBytes<4>(word, destination);
  }
  static void XorWords(const uint8_t a[4], const uint8_t b[4], uint8_t destination[4]) {
    XorBytes<4>(a, b, destination);
  }
  static const uint8_t round_constants_[11];
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_RIJNDAELKEYSCHEDULE_H_
