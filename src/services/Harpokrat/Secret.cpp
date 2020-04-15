//
// Created by neodar on 12/01/2020.
//

#include "Secret.h"
#include "../Crypto/Base64.h"
#include "../Crypto/SuperFactory.h"
#include "../Crypto/Factory.h"

HCL::Secret::Secret() {
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

HCL::Secret::Secret(const std::string &key, const std::string &content) {
  Deserialize(key, content);
}

void HCL::Secret::Deserialize(const std::string &key, const std::string &content) {
  blob_ = HCL::Crypto::EncryptedBlob(key, HCL::Crypto::Base64::Decode(content));
  std::string serialized_content = blob_.GetContent();
  const auto *serialized_header = reinterpret_cast<const SerializedSecretHeader *>(serialized_content.c_str());
  size_t offset = 8;
  size_t serialized_length = offset
      + serialized_header->fields_sizes[0]
      + serialized_header->fields_sizes[1]
      + serialized_header->fields_sizes[2]
      + serialized_header->fields_sizes[3];

  // TODO Check correct password before decryption with checksum (look at android backup method)
  if (serialized_content.size() == serialized_length) {
    decryption_error_ = false;
    name_ = serialized_content.substr(offset, serialized_header->fields_sizes[0]);
    offset += serialized_header->fields_sizes[0];
    login_ = serialized_content.substr(offset, serialized_header->fields_sizes[1]);
    offset += serialized_header->fields_sizes[1];
    password_ = serialized_content.substr(offset, serialized_header->fields_sizes[2]);
    offset += serialized_header->fields_sizes[2];
    domain_ = serialized_content.substr(offset, serialized_header->fields_sizes[3]);
  } else {
    decryption_error_ = true;
  }
}

std::string HCL::Secret::Serialize(const std::string &key) {
  std::string serialized_content;
  SerializedSecretHeader serialized_header{};

  serialized_header.fields_sizes[0] = name_.size();
  serialized_header.fields_sizes[1] = login_.size();
  serialized_header.fields_sizes[2] = password_.size();
  serialized_header.fields_sizes[3] = domain_.size();
  serialized_content += std::string(serialized_header.bytes, 8);
  serialized_content += name_;
  serialized_content += login_;
  serialized_content += password_;
  serialized_content += domain_;

  blob_.SetContent(serialized_content);
  return HCL::Crypto::Base64::Encode(blob_.GetEncryptedContent(key));
}

const std::string &HCL::Secret::GetName() const {
  return name_;
}

const std::string &HCL::Secret::GetLogin() const {
  return login_;
}

const std::string &HCL::Secret::GetPassword() const {
  return password_;
}

const std::string &HCL::Secret::GetDomain() const {
  return domain_;
}

void HCL::Secret::SetName(const std::string &name) {
  name_ = name;
}

void HCL::Secret::SetLogin(const std::string &login) {
  login_ = login;
}

void HCL::Secret::SetPassword(const std::string &password) {
  password_ = password;
}

void HCL::Secret::SetDomain(const std::string &domain) {
  domain_ = domain;
}

bool HCL::Secret::CorrectDecryption() const {
  return !decryption_error_;
}
