//
// Created by neodar on 12/01/2020.
//

#include "ASecret.h"
#include "../../Crypto/Base64.h"
#include "../../Crypto/SuperFactory.h"
#include "../../Crypto/Factory.h"
#include "Password.h"
#include "PrivateKey.h"
#include "PublicKey.h"
#include "SymmetricKey.h"

HCL::ASecret::ASecret() {
  auto sha256 = HCL::Crypto::SuperFactory::GetFactoryOfType("hash-function").BuildFromName("sha256");
  auto hmac = HCL::Crypto::SuperFactory::GetFactoryOfType("message-authentication-code").BuildFromName("hmac");
  auto mt19927_pbkdf = HCL::Crypto::SuperFactory::GetFactoryOfType("random-generator").BuildFromName("mt19937");
  auto mt19927_cbc = HCL::Crypto::SuperFactory::GetFactoryOfType("random-generator").BuildFromName("mt19937");
  auto pbkdf2 = HCL::Crypto::SuperFactory::GetFactoryOfType("key-stretching-function").BuildFromName("pbkdf2");
  auto aes256 = HCL::Crypto::SuperFactory::GetFactoryOfType("block-cipher").BuildFromName("aes256");
  auto pkcs7 = HCL::Crypto::SuperFactory::GetFactoryOfType("padding").BuildFromName("pkcs7");
  auto cbc = HCL::Crypto::SuperFactory::GetFactoryOfType("block-cipher-mode").BuildFromName("cbc");
  auto cipher = HCL::Crypto::Factory<HCL::Crypto::ACipher>::BuildTypedFromName("block-cipher-scheme");

  hmac->SetDependency(std::move(sha256), 0);
  pbkdf2->SetDependency(std::move(hmac), 0);
  pbkdf2->SetDependency(std::move(mt19927_pbkdf), 1);
  aes256->SetDependency(std::move(pbkdf2), 0);
  cbc->SetDependency(std::move(aes256), 0);
  cbc->SetDependency(std::move(pkcs7), 1);
  cbc->SetDependency(std::move(mt19927_cbc), 2);
  cipher->SetDependency(std::move(cbc), 0);

  blob_.SetCipher(std::move(cipher));
}

HCL::ASecret *HCL::ASecret::DeserializeSecret(const std::string &key, const std::string &content) {
  HCL::Crypto::EncryptedBlob blob = HCL::Crypto::EncryptedBlob(key, HCL::Crypto::Base64::Decode(content));
  std::string serialized_content = blob.GetContent();
  SecretType type = reinterpret_cast<const SecretType *>(serialized_content.c_str())[0];
  ASecret *secret;

  switch (type) {
    case PASSWORD:
      secret = static_cast<ASecret *>(new Password());
      break;
    case PRIVATE_KEY:
      secret = static_cast<ASecret *>(new PrivateKey());
      break;
    case PUBLIC_KEY:
      secret = static_cast<ASecret *>(new PublicKey());
      break;
    case SYMMETRIC_KEY:
      secret = static_cast<ASecret *>(new SymmetricKey());
      break;
  }
  secret->DeserializeContent(serialized_content.substr(1));
  return secret;
}

std::string HCL::ASecret::Serialize(const std::string &key) {
  std::string serialized_content = std::string(1, this->GetSecretType()) + SerializeContent(key);

  blob_.SetContent(serialized_content);
  return HCL::Crypto::Base64::Encode(blob_.GetEncryptedContent(key));
}

bool HCL::ASecret::CorrectDecryption() const {
  return !decryption_error_;
}
