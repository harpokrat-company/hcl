//
// Created by neodar on 28/03/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_AES_H_
#define HCL_SRC_SERVICES_CRYPTO_AES_H_

#include <cstdint>

#include "RijndaelSubstitutionBox.h"
#include "CryptoHelper.h"

namespace HCL::Crypto {

class AES {
 public:
  static void AES256(const uint8_t[32], uint8_t [4][4]);
 private:
  static void AddRoundKey(uint8_t [4][4], const uint8_t [16]);
  static void SubBytes(uint8_t [4][4]);
  static void ShiftRows(uint8_t [4][4]);
  static void MixColumn(uint8_t [4][4], uint8_t);
  static void MixColumns(uint8_t [4][4]);
};
}
#endif //HCL_SRC_SERVICES_CRYPTO_AES_H_
