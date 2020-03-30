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
  static void AES128(const uint8_t[16], uint8_t [16]);
  static void AES192(const uint8_t[24], uint8_t [16]);
  static void AES256(const uint8_t[32], uint8_t [16]);
 private:
  static void AddRoundKey(uint8_t [4][4], const uint8_t [16]);
  static void SubBytes(uint8_t [4][4]);
  static void ShiftRows(uint8_t [4][4]);
  static void MixColumn(uint8_t [4][4], uint8_t);
  static void MixColumns(uint8_t [4][4]);
  static void FlatToState(const uint8_t [16], uint8_t [4][4]);
  static void StateToFlat(const uint8_t [4][4], uint8_t [16]);
  template<uint8_t KeySize, uint8_t Rounds>
  static void Cipher(const uint8_t[KeySize], uint8_t [4][4]);
  template<uint8_t KeySize, uint8_t Rounds>
  static void FlatAES(const uint8_t[KeySize], uint8_t [16]);
};
}
#endif //HCL_SRC_SERVICES_CRYPTO_AES_H_
