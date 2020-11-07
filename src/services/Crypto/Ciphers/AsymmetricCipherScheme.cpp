//
// Created by neodar on 07/09/2020.
//

#include "AsymmetricCipherScheme.h"

HCL::Crypto::AsymmetricCipherScheme::AsymmetricCipherScheme(const std::string &header, size_t &header_length) {
  this->asymmetric_cipher_ = Factory<AAsymmetricCipher>::BuildTypedFromHeader(header, header_length);
}

std::string HCL::Crypto::AsymmetricCipherScheme::Encrypt(const ICipherEncryptionKey *key, const std::string &content) {
  if (!asymmetric_cipher_) {
    throw std::runtime_error(GetDependencyUnsetError("encrypt", "Asymmetric cipher"));
  }
  if (key->GetEncryptionKeyType() != "public") {
    throw std::runtime_error(GetError("encrypt", "Cipher encryption key is of wrong type"));
  }
  return dynamic_cast<const PublicKey *>(key)->Encrypt(content);
}

std::string HCL::Crypto::AsymmetricCipherScheme::Decrypt(const ICipherDecryptionKey *key, const std::string &content) {
  if (!asymmetric_cipher_) {
    throw std::runtime_error(GetDependencyUnsetError("decrypt", "Asymmetric cipher"));
  }
  if (key->GetDecryptionKeyType() != "private") {
    throw std::runtime_error(GetError("decrypt", "Cipher decryption key is of wrong type"));
  }
  return dynamic_cast<const PrivateKey *>(key)->Decrypt(content);
}

std::string HCL::Crypto::AsymmetricCipherScheme::GetHeader() {
  if (!asymmetric_cipher_) {
    throw std::runtime_error(GetDependencyUnsetError("get header", "Asymmetric cipher"));
  }
  return GetIdBytes() + asymmetric_cipher_->GetHeader();
}

void HCL::Crypto::AsymmetricCipherScheme::SetAsymmetricCipher(std::unique_ptr<ACryptoElement> block_cipher_mode) {
  asymmetric_cipher_ = ACryptoElement::UniqueTo<AAsymmetricCipher>(std::move(block_cipher_mode));
}

bool HCL::Crypto::AsymmetricCipherScheme::IsAsymmetricCipherSet() const {
  return !!asymmetric_cipher_;
}

HCL::Crypto::ACryptoElement &HCL::Crypto::AsymmetricCipherScheme::GetAsymmetricCipher() const {
  if (!IsAsymmetricCipherSet()) {
    throw std::runtime_error(GetDependencyUnsetError("get Asymmetric cipher", "Asymmetric cipher"));
  }
  return *asymmetric_cipher_;
}
