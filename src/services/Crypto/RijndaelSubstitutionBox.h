//
// Created by neodar on 30/03/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_RIJNDAELSUBSTITUTIONBOX_H_
#define HCL_SRC_SERVICES_CRYPTO_RIJNDAELSUBSTITUTIONBOX_H_

#include <cstdint>
namespace HCL::Crypto {

class RijndaelSubstitutionBox {
 public:
  static uint8_t SubByte(uint8_t) __attribute__((const));
  static uint8_t InvSubByte(uint8_t) __attribute__((const));
  template<uint8_t BytesNumber>
  static void SubBytes(const uint8_t [BytesNumber], uint8_t [BytesNumber]);
  template<uint8_t BytesNumber>
  static void InvSubBytes(const uint8_t [BytesNumber], uint8_t [BytesNumber]);
  static void SubWord(const uint8_t word[4], uint8_t destination[4]);
  static void InvSubWord(const uint8_t word[4], uint8_t destination[4]);
 private:
  static const uint8_t substitution_box_[256];
  static const uint8_t reverse_substitution_box_[256];
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_RIJNDAELSUBSTITUTIONBOX_H_
