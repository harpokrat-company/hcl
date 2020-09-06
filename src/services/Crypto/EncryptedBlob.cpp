//
// Created by neodar on 06/04/2020.
//

#include "EncryptedBlob.h"
#include "Factory.h"

HCL::Crypto::EncryptedBlob::EncryptedBlob(const std::string &key, const std::string &content) {
  size_t header_length = 0;

  SetCipher(Factory<ACipher>::BuildTypedFromHeader(content, header_length));
  SetEncryptedContent(key, content.substr(header_length));
}

void HCL::Crypto::EncryptedBlob::SetEncryptedContent(const std::string &key, const std::string &content) {
  if (!cipher_) {
    throw std::runtime_error("EncryptedBlob: Cannot decrypt content: No cipher is set");
  }
  SetContent(cipher_->Decrypt(key, content));
}

void HCL::Crypto::EncryptedBlob::SetCipher(std::unique_ptr<ACipher> cipher) {
  cipher_ = std::move(cipher);
}

void HCL::Crypto::EncryptedBlob::SetContent(const std::string &content) {
  // TODO ASecret constructor when specified ?
  content_ = content;
}

std::string HCL::Crypto::EncryptedBlob::GetContent() {
  // TODO ASecret constructor when specified ?
  return content_;
}

std::string HCL::Crypto::EncryptedBlob::GetEncryptedContent(const std::string &key) {
  if (!cipher_) {
    throw std::runtime_error("EncryptedBlob: Cannot encrypt content: No cipher is set");
  }
  return cipher_->GetHeader() + cipher_->Encrypt(key, content_);
}
