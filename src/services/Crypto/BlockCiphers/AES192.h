//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES192_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES192_H_

#include "../AutoRegisterer.h"
#include "ABlockCipher.h"
#include "Rijndael.h"

namespace HCL::Crypto {

class AES192 : public AutoRegisterer<ABlockCipher, AES192>, public Rijndael<24, 12> {
 public:
  AES192() = default;
  AES192(const std::string &header, size_t &header_length) : Rijndael<24, 12>(header, header_length) {
    is_registered_;
  };
  std::string GetHeader() override;
  const std::string &GetElementName() override { return GetName(); };
  const std::string &GetElementTypeName() override { return GetTypeName(); };
  static const uint16_t id = 2;
  static const std::string &GetName() {
    static std::string name = "aes192";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_AES192_H_
