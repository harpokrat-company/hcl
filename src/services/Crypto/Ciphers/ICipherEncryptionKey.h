//
// Created by neodar on 07/09/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_CIPHERS_ICIPHERENCRYPTIONKEY_H_
#define HCL_SRC_SERVICES_CRYPTO_CIPHERS_ICIPHERENCRYPTIONKEY_H_

#include <string>

namespace HCL::Crypto {
class ICipherEncryptionKey {
 public:
  virtual const std::string &GetEncryptionKeyType() const = 0;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_CIPHERS_ICIPHERENCRYPTIONKEY_H_
