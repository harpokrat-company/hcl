//
// Created by neodar on 12/01/2020.
//

#ifndef HCL_SECRET_H
#define HCL_SECRET_H

#include <string>
#include "../Crypto/EncryptedBlob.h"

namespace HCL {
union SerializedSecretHeader {
  uint16_t fields_sizes[4];
  char bytes[8];
};

class Secret {
 public:
  explicit Secret();
  // TODO optional key and decrypt when needed (IsDecrypted & Decrypt(key)) (in blob ?)
  //  Probably change working principle to be always encrypted and decrypt when needed only
  explicit Secret(const std::string &key, const std::string &content);
  [[nodiscard]] std::string Serialize(const std::string &key);
  [[nodiscard]] const std::string &GetName() const;
  [[nodiscard]] const std::string &GetLogin() const;
  [[nodiscard]] const std::string &GetPassword() const;
  [[nodiscard]] const std::string &GetDomain() const;
  void SetName(const std::string &);
  void SetLogin(const std::string &);
  void SetPassword(const std::string &);
  void SetDomain(const std::string &);
  bool CorrectDecryption() const;

 private:
  std::string name_;
  std::string login_;
  std::string password_;
  std::string domain_;
  // TODO Change behaviour via throwing (find how to catch in every wrapper)
  bool decryption_error_ = false;
  // TODO Move blob somewhere else & implement API for customization of crypto workflow
  HCL::Crypto::EncryptedBlob blob_;

  void Deserialize(const std::string &key, const std::string &content);
};
}

#endif //HCL_SECRET_H
