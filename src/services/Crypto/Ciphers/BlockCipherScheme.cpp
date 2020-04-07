//
// Created by neodar on 06/04/2020.
//

#include "BlockCipherScheme.h"

const std::string HCL::Crypto::BlockCipherScheme::name = "block-cipher-scheme";

HCL::Crypto::BlockCipherScheme::BlockCipherScheme(const std::string &header, size_t &header_length) {
  is_registered_;
  this->block_cipher_mode_ = Factory<ABlockCipherMode>::GetInstanceFromHeader(header, header_length);
}

std::string HCL::Crypto::BlockCipherScheme::Encrypt(const std::string &password, const std::string &content) {
  return block_cipher_mode_->Encrypt(password, content);
}

std::string HCL::Crypto::BlockCipherScheme::Decrypt(const std::string &password, const std::string &content) {
  return block_cipher_mode_->Decrypt(password, content);
}
std::string HCL::Crypto::BlockCipherScheme::GetHeader() {
  return GetIdBytes() + block_cipher_mode_->GetHeader();
}
