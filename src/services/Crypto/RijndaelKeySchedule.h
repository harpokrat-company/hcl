//
// Created by neodar on 28/03/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_RIJNDAELKEYSCHEDULE_H_
#define HCL_SRC_SERVICES_CRYPTO_RIJNDAELKEYSCHEDULE_H_

#include <cstdint>

#include "RijndaelSubstitutionBox.h"
#include "CryptoHelper.h"

#define WORD_AT(variable, at)         (variable[(at) / 4] + ((at) % 4) * 4)

namespace HCL::Crypto {

class RijndaelKeySchedule {
 public:
  template<uint8_t KeySize, uint8_t RoundKeys>
  static void KeyExpansion(const uint8_t [KeySize], uint8_t [RoundKeys][16]);
 private:
  static const uint8_t round_constants_[11];
};
}

#include "RijndaelKeySchedule.tpp"

#endif //HCL_SRC_SERVICES_CRYPTO_RIJNDAELKEYSCHEDULE_H_
