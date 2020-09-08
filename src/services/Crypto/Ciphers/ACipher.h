//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_CIPHERS_ACIPHER_H_
#define HCL_SRC_SERVICES_CRYPTO_CIPHERS_ACIPHER_H_

#include <string>
#include <memory>
#include "../ACryptoElement.h"
#include "ICipherEncryptionKey.h"
#include "ICipherDecryptionKey.h"

namespace HCL::Crypto {

class ACipher : public ACryptoElement {
 public:
  virtual ~ACipher() = default;
  virtual std::string Encrypt(const ICipherEncryptionKey *key, const std::string &content) = 0;
  virtual std::string Decrypt(const ICipherDecryptionKey *key, const std::string &content) = 0;
  virtual std::string GetHeader() = 0;
  static const std::string &GetName() {
    static std::string name = "cipher";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_CIPHERS_ACIPHER_H_
