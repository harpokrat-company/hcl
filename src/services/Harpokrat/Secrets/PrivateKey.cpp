//
// Created by neodar on 06/09/2020.
//

#include "PrivateKey.h"
#include "../../Crypto/AsymmetricCiphers/RSA.h"

#include <utility>

HCL::PrivateKey::PrivateKey(__mpz_struct modulus, __mpz_struct private_key) :
    PrivateKey() {
  modulus_ = modulus;
  private_key_ = private_key;
}

HCL::PrivateKey::PrivateKey(const HCL::Crypto::RSAKey &key_pair) :
    PrivateKey(key_pair.GetModulus(), key_pair.GetKey()) {}

bool HCL::PrivateKey::DeserializeContent(const std::string &content) {
  __mpz_struct gmp_value;
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
    mpz_import(&gmp_value, serialized_header->fields_sizes[1],
               1, sizeof(char), 1, 0, content.c_str() + offset);
    modulus_ = gmp_value;
    offset += serialized_header->fields_sizes[1];
    mpz_import(&gmp_value, serialized_header->fields_sizes[2],
               1, sizeof(char), 1, 0, content.c_str() + offset);
    private_key_ = gmp_value;
    return false;
  } else {
    return true;
  }
}

std::string HCL::PrivateKey::SerializeContent() const {
  std::string serialized_content;
  SerializedPrivateKeyHeader serialized_header{};

  serialized_header.fields_sizes[0] = owner_.size();
  serialized_header.fields_sizes[1] = mpz_sizeinbase(&(this->modulus_), 2) / sizeof(char);
  serialized_header.fields_sizes[2] = mpz_sizeinbase(&(this->private_key_), 2) / sizeof(char);
  char serialized_modulus[serialized_header.fields_sizes[1]];
  char serialized_private_key[serialized_header.fields_sizes[2]];
  mpz_export(serialized_modulus, nullptr, 1, sizeof(char), 1, 0, &modulus_);
  mpz_export(serialized_private_key, nullptr, 1, sizeof(char), 1, 0, &private_key_);
  serialized_content += std::string(serialized_header.bytes, 8);
  serialized_content += owner_;
  serialized_content += serialized_modulus;
  serialized_content += serialized_private_key;
  return serialized_content;
}

std::string HCL::PrivateKey::Decrypt(const std::string &message) const {
  return HCL::Crypto::RSA::RSADecrypt(modulus_, private_key_, message);
}

const std::string &HCL::PrivateKey::GetOwner() const {
  return owner_;
}

void HCL::PrivateKey::SetOwner(const std::string &owner) {
  this->owner_ = owner;
}

HCL::Crypto::RSAKey HCL::PrivateKey::ExtractKey() const {
  return Crypto::RSAKey(modulus_, private_key_);
}
