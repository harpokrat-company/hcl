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
  virtual std::string EncryptBloc(const std::string &key, const std::string &bloc) = 0;
  virtual std::string DecryptBloc(const std::string &key, const std::string &bloc) = 0;
  virtual size_t GetBlockSize() __attribute__((const)) = 0;
  virtual std::string PrepareKey(const std::string &key) __attribute__((const)) = 0;
  virtual std::string GetHeader() = 0;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_ABLOCKCIPHER_H_
