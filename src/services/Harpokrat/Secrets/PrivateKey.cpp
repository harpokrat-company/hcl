//
// Created by neodar on 06/09/2020.
//

#include "PrivateKey.h"
#include "../../Crypto/AsymmetricCiphers/RSA.h"

#include <utility>

HCL::PrivateKey::PrivateKey(mpz_class modulus, mpz_class private_key) :
  PrivateKey() {
  modulus_ = std::move(modulus);
  private_key_ = std::move(private_key);
}

bool HCL::PrivateKey::DeserializeContent(const std::string &content) {
  mpz_t gmp_value;
  const auto *serialized_header = reinterpret_cast<const SerializedPrivateKeyHeader *>(content.c_str());
  size_t offset = 6;
  size_t serialized_length = offset
      + serialized_header->fields_sizes[0]
      + serialized_header->fields_sizes[1]
      + serialized_header->fields_sizes[2];

  // TODO Check correct before decryption with checksum (look at android backup method)
  if (content.size() == serialized_length) {
    owner_ = content.substr(offset, serialized_header->fields_sizes[0]);
    offset += serialized_header->fields_sizes[0];
    mpz_import(gmp_value, serialized_header->fields_sizes[1],
               1, sizeof(char), 1, 0, content.c_str() + offset);
    modulus_ = mpz_class(gmp_value);
    offset += serialized_header->fields_sizes[1];
    mpz_import(gmp_value, serialized_header->fields_sizes[2],
               1, sizeof(char), 1, 0, content.c_str() + offset);
    private_key_ = mpz_class(gmp_value);
    return false;
  } else {
    return true;
  }
}

std::string HCL::PrivateKey::SerializeContent(const std::string &key) const {
  std::string serialized_content;
  SerializedPrivateKeyHeader serialized_header{};

  serialized_header.fields_sizes[0] = owner_.size();
  serialized_header.fields_sizes[1] = mpz_sizeinbase(this->modulus_.get_mpz_t(), 2) / sizeof(char);
  serialized_header.fields_sizes[2] = mpz_sizeinbase(this->private_key_.get_mpz_t(), 2) / sizeof(char);
  char serialized_modulus[serialized_header.fields_sizes[1]];
  char serialized_private_key[serialized_header.fields_sizes[2]];
  mpz_export(serialized_modulus, nullptr, 1, sizeof(char), 1, 0, modulus_.get_mpz_t());
  mpz_export(serialized_private_key, nullptr, 1, sizeof(char), 1, 0, private_key_.get_mpz_t());
  serialized_content += std::string(serialized_header.bytes, 8);
  serialized_content += owner_;
  serialized_content += serialized_modulus;
  serialized_content += serialized_private_key;
  return serialized_content;
}

std::string HCL::PrivateKey::Decrypt(const std::string &message) {
  return HCL::Crypto::RSA::RSADecrypt(modulus_, private_key_, message);
}

const std::string &HCL::PrivateKey::GetOwner() const {
  return owner_;
}

void HCL::PrivateKey::SetOwner(const std::string &owner) {
  this->owner_ = owner;
}
