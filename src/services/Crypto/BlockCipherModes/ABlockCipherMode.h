//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_ABLOCKCIPHERMODE_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_ABLOCKCIPHERMODE_H_

#include <cstddef>
#include <string>
#include <memory>
#include "../BlockCiphers/ABlockCipher.h"
#include "../AutoRegistrable.h"

namespace HCL::Crypto {

class ABlockCipherMode : public AutoRegistrable {
 public:
  ABlockCipherMode() = default;
  ABlockCipherMode(const std::string &header, size_t &header_length);
  virtual std::string Encrypt(const std::string &key, const std::string &content) = 0;
  virtual std::string Decrypt(const std::string &key, const std::string &content) = 0;
  virtual std::string GetHeader();
  void SetCipher(std::unique_ptr<AutoRegistrable> cipher);
  static const std::string &GetName() {
    static std::string name = "block-cipher-mode";
    return name;
  };
 protected:
  std::unique_ptr<ABlockCipher> cipher_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERS_ABLOCKCIPHERMODE_H_
