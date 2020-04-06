//
// Created by neodar on 28/03/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_AES_H_
#define HCL_SRC_SERVICES_CRYPTO_AES_H_

#include <cstdint>

#include "../RijndaelSubstitutionBox.h"
#include "../CryptoHelper.h"

namespace HCL::Crypto {

class AES {
 public:
  template<uint8_t KeySize, uint8_t Rounds>
  static void EncryptBloc(const uint8_t[KeySize], uint8_t [16]);
  template<uint8_t KeySize, uint8_t Rounds>
  static void DecryptBloc(const uint8_t[KeySize], uint8_t [16]);
  static void AES128Encrypt(const uint8_t[16], uint8_t [16]);
  static void AES192Encrypt(const uint8_t[24], uint8_t [16]);
  static void AES256Encrypt(const uint8_t[32], uint8_t [16]);
  static void AES128Decrypt(const uint8_t[16], uint8_t [16]);
  static void AES192Decrypt(const uint8_t[24], uint8_t [16]);
  static void AES256Decrypt(const uint8_t[32], uint8_t [16]);
 private:
  static void AddRoundKey(uint8_t [4][4], const uint8_t [16]);
  static void SubBytes(uint8_t [4][4]);
  static void ShiftRows(uint8_t [4][4]);
  static uint8_t GaloisProduct(uint8_t, uint8_t);
  static uint8_t GaloisColumnProduct(const uint8_t [4], const uint8_t [4]);
  static void MixColumn(uint8_t [4][4], uint8_t);
  static void MixColumns(uint8_t [4][4]);
  static void InvSubBytes(uint8_t [4][4]);
  static void InvShiftRows(uint8_t [4][4]);
  static void InvMixColumn(uint8_t [4][4], uint8_t);
  static void InvMixColumns(uint8_t [4][4]);
  static void BlocToState(const uint8_t [16], uint8_t [4][4]);
  static void StateToBloc(const uint8_t [4][4], uint8_t [16]);
  template<uint8_t KeySize, uint8_t Rounds>
  static void EncryptState(const uint8_t[KeySize], uint8_t [4][4]);
  template<uint8_t KeySize, uint8_t Rounds>
  static void DecryptState(const uint8_t[KeySize], uint8_t [4][4]);
};
}
#endif //HCL_SRC_SERVICES_CRYPTO_AES_H_
