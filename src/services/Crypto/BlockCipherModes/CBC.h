//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_CBC_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_CBC_H_

#include "ABlockCipherMode.h"
#include "../AutoRegisterer.h"
#include "../Padding/APaddedCipher.h"
#include "AInitializationVectorBlockCipherMode.h"

namespace HCL::Crypto {

class CBC : public AutoRegisterer<ABlockCipherMode, CBC>,
            public APaddedCipher,
            public AInitializationVectorBlockCipherMode {
 public:
  CBC(const std::string &header, size_t &header_length);
  std::string Encrypt(const std::string &key, const std::string &content) override;
  std::string Decrypt(const std::string &key, const std::string &content) override;
  static const uint16_t id = 1;
  static const std::string &GetName() {
    static std::string name = "cbc";
    return name;
  };
  std::string GetHeader() override;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_CBC_H_
