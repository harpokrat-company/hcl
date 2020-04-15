//
// Created by neodar on 06/04/2020.
//

#include "BlockCipherScheme.h"

HCL::Crypto::BlockCipherScheme::BlockCipherScheme(const std::string &header, size_t &header_length) {
  this->block_cipher_mode_ = Factory<ABlockCipherMode>::BuildTypedFromHeader(header, header_length);
}

std::string HCL::Crypto::BlockCipherScheme::Encrypt(const std::string &password, const std::string &content) {
  if (!block_cipher_mode_) {
    throw std::runtime_error("BlockCipherScheme error: Block cipher mode is not set");
  }
  return block_cipher_mode_->Encrypt(password, content);
}

std::string HCL::Crypto::BlockCipherScheme::Decrypt(const std::string &password, const std::string &content) {
  if (!block_cipher_mode_) {
    throw std::runtime_error("BlockCipherScheme error: Block cipher mode is not set");
  }
  return block_cipher_mode_->Decrypt(password, content);
}
std::string HCL::Crypto::BlockCipherScheme::GetHeader() {
  if (!block_cipher_mode_) {
    throw std::runtime_error("BlockCipherScheme error: Block cipher mode is not set");
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
    throw std::runtime_error("BlockCipherScheme: Cannot get Block Cipher Mode: Not set");
  }
  return *block_cipher_mode_;
}
