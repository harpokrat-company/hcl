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
  static void AES128KeyExpansion(const uint8_t [16], uint8_t [11][16]);
  static void AES192KeyExpansion(const uint8_t [24], uint8_t [13][16]);
  static void AES256KeyExpansion(const uint8_t [32], uint8_t [15][16]);
 private:
  template<uint8_t BytesNumber>
  static void CopyBytes(const uint8_t [BytesNumber], uint8_t [BytesNumber]);
  template<uint8_t BytesNumber>
  static void RotBytes(const uint8_t [BytesNumber], uint8_t [BytesNumber]);
  template<uint8_t BytesNumber>
  static void XorBytes(const uint8_t [BytesNumber], const uint8_t [BytesNumber], uint8_t [BytesNumber]);
  static void CopyWord(const uint8_t word[4], uint8_t destination[4]);
  static void RotWord(const uint8_t word[4], uint8_t destination[4]);
  static void XorWords(const uint8_t a[4], const uint8_t b[4], uint8_t destination[4]);
  static const uint8_t round_constants_[11];
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_RIJNDAELKEYSCHEDULE_H_
