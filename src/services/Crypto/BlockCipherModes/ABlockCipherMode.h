//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_ABLOCKCIPHERMODE_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_ABLOCKCIPHERMODE_H_

#include <cstddef>
#include <string>
#include <memory>
#include "../BlockCiphers/ABlockCipher.h"

namespace HCL::Crypto {

class ABlockCipherMode {
 public:
  ABlockCipherMode(const std::string &header, size_t &header_length);
  virtual std::string Encrypt(const std::string &key, const std::string &content) = 0;
  virtual std::string Decrypt(const std::string &key, const std::string &content) = 0;
  virtual std::string GetHeader();
 protected:
  std::unique_ptr<ABlockCipher> cipher_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_ABLOCKCIPHERMODE_H_
