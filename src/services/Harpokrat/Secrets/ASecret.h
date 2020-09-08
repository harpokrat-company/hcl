//
// Created by neodar on 12/01/2020.
//

#ifndef HCL_SECRET_H
#define HCL_SECRET_H

#include <string>
#include "../../Crypto/EncryptedBlob.h"
#include "../../Crypto/Ciphers/ICipherDecryptionKey.h"
#include "../../Crypto/Ciphers/ICipherEncryptionKey.h"

namespace HCL {
enum SecretType : char {
  PASSWORD,
  PRIVATE_KEY,
  PUBLIC_KEY,
  SYMMETRIC_KEY
};

//-> RSAPrivateKey
//-> RSAPublicKey
//-> Password
//-> Textual notes
//-> Credit card
//-> SymmetricKey
class ASecret {
 public:
  virtual ~ASecret() = default;
  void InitializeAsymmetricCipher();
  void InitializeSymmetricCipher();
  // TODO optional key and decrypt when needed (IsDecrypted & Decrypt(key)) (in blob ?)
  //  Probably change working principle to be always encrypted and decrypt when needed only
  static ASecret *DeserializeSecret(const Crypto::ICipherDecryptionKey *key, const std::string &content);
  [[nodiscard]] std::string Serialize(const Crypto::ICipherEncryptionKey *key);
  [[nodiscard]] bool CorrectDecryption() const;
  [[nodiscard]] const std::string &GetSecretTypeName() const;

 protected:
  ASecret() = default;
  [[nodiscard]] virtual SecretType GetSecretType() const = 0;
  [[nodiscard]] virtual std::string SerializeContent() const = 0;
  virtual bool DeserializeContent(const std::string &content) = 0;

 private:
  // TODO Change behaviour via throwing (find how to catch in every wrapper)
  bool decryption_error_ = false;
  // TODO Move blob somewhere else & implement API for customization of crypto workflow
  HCL::Crypto::EncryptedBlob blob_;
  static const std::map<SecretType, const std::string> type_names_;
};
}

#endif //HCL_SECRET_H
