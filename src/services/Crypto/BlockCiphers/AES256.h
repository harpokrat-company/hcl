//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES256_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES256_H_

#include "../AutoRegisterer.h"
#include "ABlockCipher.h"
#include "Rijndael.h"

namespace HCL::Crypto {

class AES256 : public AutoRegisterer<ABlockCipher, AES256>, public Rijndael<32, 14> {
 public:
  AES256() = default;
  AES256(const std::string &header, size_t &header_length) : Rijndael<32, 14>(header, header_length) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-value"
    is_registered_;
#pragma GCC diagnostic pop
  };
  std::string GetHeader() override;
  const std::string &GetElementName() override { return GetName(); };
  const std::string &GetElementTypeName() override { return GetTypeName(); };
  static const uint16_t id = 3;
  static const std::string &GetName() {
    static std::string name = "aes256";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES256_H_
