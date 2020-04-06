//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_ABLOCKCIPHER_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_ABLOCKCIPHER_H_

#include <cstddef>
#include <string>
#include <memory>
#include "../KeyStretching/AKeyStretching.h"

namespace HCL::Crypto {

class ABlockCipher {
 public:
  ABlockCipher(const std::string &header, size_t &header_length);
  virtual std::string EncryptBloc(const std::string &key, const std::string &bloc) = 0;
  virtual std::string DecryptBloc(const std::string &key, const std::string &bloc) = 0;
  virtual size_t GetBlockSize() __attribute__((const)) = 0;
 protected:
  std::unique_ptr<AKeyStretching> key_stretching_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_ABLOCKCIPHER_H_
