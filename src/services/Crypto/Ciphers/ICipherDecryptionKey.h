//
// Created by neodar on 07/09/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_CIPHERS_ICIPHERDECRYPTIONKEY_H_
#define HCL_SRC_SERVICES_CRYPTO_CIPHERS_ICIPHERDECRYPTIONKEY_H_

#include <string>

namespace HCL::Crypto {
class ICipherDecryptionKey {
 public:
  virtual const std::string &GetDecryptionKeyType() const = 0;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_CIPHERS_ICIPHERDECRYPTIONKEY_H_
