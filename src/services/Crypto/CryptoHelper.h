//
// Created by neodar on 30/03/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_CRYPTOHELPER_H_
#define HCL_SRC_SERVICES_CRYPTO_CRYPTOHELPER_H_

#include <cstdint>
namespace HCL::Crypto {

class CryptoHelper {
 public:
  template<uint8_t BytesNumber>
  static void CopyBytes(const uint8_t [BytesNumber], uint8_t [BytesNumber]);
  template<uint8_t BytesNumber>
  static void RotBytes(const uint8_t [BytesNumber], uint8_t [BytesNumber]);
  template<uint8_t BytesNumber>
  static void InvRotBytes(const uint8_t [BytesNumber], uint8_t [BytesNumber]);
  template<uint8_t BytesNumber>
  static void XorBytes(const uint8_t [BytesNumber], const uint8_t [BytesNumber], uint8_t [BytesNumber]);
  static void CopyWord(const uint8_t word[4], uint8_t destination[4]);
  static void RotWord(const uint8_t word[4], uint8_t destination[4]);
  static void InvRotWord(const uint8_t word[4], uint8_t destination[4]);
  static void XorWords(const uint8_t a[4], const uint8_t b[4], uint8_t destination[4]);
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_CRYPTOHELPER_H_
