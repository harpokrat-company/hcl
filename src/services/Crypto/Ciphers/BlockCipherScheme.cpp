//
// Created by neodar on 06/04/2020.
//

#include "BlockCipherScheme.h"

HCL::Crypto::BlockCipherScheme::BlockCipherScheme(const std::string &header, size_t &header_length) {
  this->block_cipher_mode_ = Factory<ABlockCipherMode>::GetInstanceFromHeader(header, header_length);
}

std::string HCL::Crypto::BlockCipherScheme::Encrypt(const std::string &password, const std::string &content) {
  return block_cipher_mode_->Encrypt(password, content);
}

std::string HCL::Crypto::BlockCipherScheme::Decrypt(const std::string &password, const std::string &content) {
  return block_cipher_mode_->Decrypt(password, content);
}