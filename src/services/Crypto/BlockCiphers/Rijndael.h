//
// Created by neodar on 28/03/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_AES_H_
#define HCL_SRC_SERVICES_CRYPTO_AES_H_

#include <cstdint>

#include "../RijndaelSubstitutionBox.h"
#include "../CryptoHelper.h"
#include "ABlockCipher.h"

namespace HCL::Crypto {

template<uint8_t KeySize, uint8_t Rounds>
class Rijndael : virtual public ABlockCipher {
 public:
  Rijndael(const std::string &header, size_t &header_length) : ABlockCipher(header, header_length) {};
  std::string EncryptBloc(const std::string &key, const std::string &bloc) override;
  std::string DecryptBloc(const std::string &key, const std::string &bloc) override;
  size_t GetBlockSize() override __attribute__((const));
  std::string PrepareKey(const std::string &key) override __attribute__((const));
 private:
  static void EncryptArrayBloc(const uint8_t[KeySize], uint8_t [16]);
  static void DecryptArrayBloc(const uint8_t[KeySize], uint8_t [16]);
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
  static void EncryptState(const uint8_t[KeySize], uint8_t [4][4]);
  static void DecryptState(const uint8_t[KeySize], uint8_t [4][4]);
};
}
#endif //HCL_SRC_SERVICES_CRYPTO_AES_H_
