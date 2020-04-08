//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_CIPHERS_ACIPHER_H_
#define HCL_SRC_SERVICES_CRYPTO_CIPHERS_ACIPHER_H_

#include <string>
#include <memory>
#include "../AutoRegistrable.h"

namespace HCL::Crypto {

class ACipher : public AutoRegistrable {
 public:
  virtual std::string Encrypt(const std::string &key, const std::string &content) = 0;
  virtual std::string Decrypt(const std::string &key, const std::string &content) = 0;
  virtual std::string GetHeader() = 0;
  static const std::string &GetName() {
    static std::string name = "cipher";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_CIPHERS_ACIPHER_H_
