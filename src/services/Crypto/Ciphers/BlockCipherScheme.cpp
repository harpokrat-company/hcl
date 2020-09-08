//
// Created by neodar on 06/04/2020.
//

#include "BlockCipherScheme.h"
#include "../../Harpokrat/Secrets/SymmetricKey.h"

HCL::Crypto::BlockCipherScheme::BlockCipherScheme(const std::string &header, size_t &header_length) {
  this->block_cipher_mode_ = Factory<ABlockCipherMode>::BuildTypedFromHeader(header, header_length);
}

std::string HCL::Crypto::BlockCipherScheme::Encrypt(const ICipherEncryptionKey *password, const std::string &content) {
  if (!block_cipher_mode_) {
    throw std::runtime_error(GetDependencyUnsetError("encrypt", "Block cipher mode"));
  }
  if (password->GetEncryptionKeyType() != "symmetric") {
    throw std::runtime_error(GetError("encrypt", "Cipher encryption key is of wrong type"));
  }
  return block_cipher_mode_->Encrypt(dynamic_cast<const SymmetricKey *>(password)->GetKey(), content);
}

std::string HCL::Crypto::BlockCipherScheme::Decrypt(const ICipherDecryptionKey *password, const std::string &content) {
  if (!block_cipher_mode_) {
    throw std::runtime_error(GetDependencyUnsetError("decrypt", "Block cipher mode"));
  }
  if (password->GetDecryptionKeyType() != "symmetric") {
    throw std::runtime_error(GetError("decrypt", "Cipher decryption key is of wrong type"));
  }
  return block_cipher_mode_->Decrypt(dynamic_cast<const SymmetricKey *>(password)->GetKey(), content);
}

std::string HCL::Crypto::BlockCipherScheme::GetHeader() {
  if (!block_cipher_mode_) {
    throw std::runtime_error(GetDependencyUnsetError("get header", "Block cipher mode"));
  }
  return GetIdBytes() + block_cipher_mode_->GetHeader();
}

void HCL::Crypto::BlockCipherScheme::SetBlockCipherMode(std::unique_ptr<ACryptoElement> block_cipher_mode) {
  block_cipher_mode_ = ACryptoElement::UniqueTo<ABlockCipherMode>(std::move(block_cipher_mode));
}

bool HCL::Crypto::BlockCipherScheme::IsBlockCipherModeSet() const {
  return !!block_cipher_mode_;
}

HCL::Crypto::ACryptoElement &HCL::Crypto::BlockCipherScheme::GetBlockCipherMode() const {
  if (!IsBlockCipherModeSet()) {
    throw std::runtime_error(GetDependencyUnsetError("get Block cipher mode", "Block cipher mode"));
  }
  return *block_cipher_mode_;
}
