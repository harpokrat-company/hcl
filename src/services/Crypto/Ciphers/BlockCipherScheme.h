//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_CIPHERS_BLOCKCIPHERSCHEME_H_
#define HCL_SRC_SERVICES_CRYPTO_CIPHERS_BLOCKCIPHERSCHEME_H_

#include "ACipher.h"
#include "../AutoRegisterer.h"

namespace HCL::Crypto {

class BlockCipherScheme : public AutoRegisterer<ACipher, BlockCipherScheme> {
 public:
  BlockCipherScheme(const std::string &header, size_t &header_length);
  std::string Encrypt(const std::string &key, const std::string &content) override;
  std::string Decrypt(const std::string &key, const std::string &content) override;
  static const uint16_t Id = 1;
 private:
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_CIPHERS_BLOCKCIPHERSCHEME_H_
