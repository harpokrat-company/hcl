//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES128_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES128_H_

#include "../AutoRegisterer.h"
#include "ABlockCipher.h"
#include "Rijndael.h"

namespace HCL::Crypto {

class AES128 : public AutoRegisterer<ABlockCipher, AES128>, public Rijndael<16, 10> {
 public:
  AES128() = default;
  AES128(const std::string &header, size_t &header_length) : Rijndael<16, 10>(header, header_length) {
    is_registered_;
  };
  std::string GetHeader() override;
  const std::string &GetElementName() override { return GetName(); };
  const std::string &GetElementTypeName() override { return GetTypeName(); };
  static const uint16_t id = 1;
  static const std::string &GetName() {
    static std::string name = "aes128";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES128_H_
