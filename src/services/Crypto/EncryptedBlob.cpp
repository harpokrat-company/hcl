//
// Created by neodar on 06/04/2020.
//

#include "EncryptedBlob.h"
#include "Factory.h"

HCL::Crypto::EncryptedBlob::EncryptedBlob(const std::string &key, const std::string &blob) {
  size_t header_length = 0;

  this->SetCipher(Factory<ACipher>::BuildTypedFromHeader(blob, header_length));
  this->SetContent(this->cipher_->Decrypt(key, blob.substr(header_length)));
}

void HCL::Crypto::EncryptedBlob::SetCipher(std::unique_ptr<ACipher> cipher) {
  this->cipher_ = std::move(cipher);
}

void HCL::Crypto::EncryptedBlob::SetContent(const std::string &content) {
  // TODO Secret constructor when specified ?
  this->content_ = content;
}

std::string HCL::Crypto::EncryptedBlob::GetContent() {
  // TODO Secret constructor when specified ?
  return this->content_;
}

std::string HCL::Crypto::EncryptedBlob::GetEncryptedContent(const std::string &key) {
  if (!this->cipher_)
    throw std::runtime_error("EncryptedBlob: Cannot encrypt content: No cipher is set");
  return this->cipher_->Encrypt(key, this->content_);
}
