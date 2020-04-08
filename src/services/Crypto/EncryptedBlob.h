//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_ENCRYPTEDBLOB_H_
#define HCL_SRC_SERVICES_CRYPTO_ENCRYPTEDBLOB_H_

#include <memory>
#include <string>
#include <exception>
#include "Ciphers/ACipher.h"

namespace HCL::Crypto {

// TODO Change working principle to be always encrypted and decrypt when needed only
class EncryptedBlob {
 public:
  EncryptedBlob() = default;
  EncryptedBlob(const std::string &key, const std::string &blob);
  void SetCipher(std::unique_ptr<ACipher>);
  void SetContent(const std::string &content);
  void SetEncryptedContent(const std::string &key, const std::string &content);
  std::string GetContent();
  std::string GetEncryptedContent(const std::string &key);
 private:
  std::unique_ptr<ACipher> cipher_;
  std::string content_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_ENCRYPTEDBLOB_H_
