//
// Created by neodar on 06/09/2020.
//

#include "PublicKey.h"

#include <utility>
#include "../../Crypto/AsymmetricCiphers/RSA.h"

HCL::PublicKey::PublicKey(mpz_class modulus, mpz_class public_key) :
    PublicKey() {
  modulus_ = std::move(modulus);
  public_key_ = std::move(public_key);
}

HCL::PublicKey::PublicKey(const HCL::Crypto::RSAKey *key_pair) :
    PublicKey(key_pair->GetModulus(), key_pair->GetKey()) {}

bool HCL::PublicKey::DeserializeContent(const std::string &content) {
  mpz_t modulus_value;
  mpz_init(modulus_value);
  mpz_t public_value;
  mpz_init(public_value);
  const auto *serialized_header = reinterpret_cast<const SerializedPublicKeyHeader *>(content.c_str());
  size_t offset = 6;
  size_t serialized_length = offset
      + serialized_header->fields_sizes[0]
      + serialized_header->fields_sizes[1]
      + serialized_header->fields_sizes[2];

  if (content.size() == serialized_length) {
    owner_ = content.substr(offset, serialized_header->fields_sizes[0]);
    offset += serialized_header->fields_sizes[0];
    mpz_import(modulus_value, serialized_header->fields_sizes[1], 1, sizeof(char), 0, 0, content.c_str() + offset);
    modulus_ = mpz_class(modulus_value);
    offset += serialized_header->fields_sizes[1];
    mpz_import(public_value, serialized_header->fields_sizes[2], 1, sizeof(char), 0, 0, content.c_str() + offset);
    public_key_ = mpz_class(public_value);
    return false;
  } else {
    return true;
  }
}

std::string HCL::PublicKey::SerializeContent() const {
  std::string serialized_content;
  SerializedPublicKeyHeader serialized_header{};

  serialized_header.fields_sizes[0] = owner_.size();
  serialized_header.fields_sizes[1] = (this->modulus_.get_mpz_t()->_mp_size * (sizeof(mp_limb_t) * 8)) / 8;
  serialized_header.fields_sizes[2] = (this->public_key_.get_mpz_t()->_mp_size * (sizeof(mp_limb_t) * 8)) / 8;
  char serialized_modulus[serialized_header.fields_sizes[1]];
  char serialized_public_key[serialized_header.fields_sizes[2]];
  mpz_export(serialized_modulus, nullptr, 1, sizeof(char), 0, 0, modulus_.get_mpz_t());
  mpz_export(serialized_public_key, nullptr, 1, sizeof(char), 0, 0, public_key_.get_mpz_t());
  serialized_content += std::string(serialized_header.bytes, 6);
  serialized_content += owner_;
  serialized_content += std::string(serialized_modulus, serialized_header.fields_sizes[1]);
  serialized_content += std::string(serialized_public_key, serialized_header.fields_sizes[2]);
  return serialized_content;
}

std::string HCL::PublicKey::Encrypt(const std::string &message) const {
  return HCL::Crypto::RSA::RSAEncrypt(modulus_, public_key_, message);
}

const std::string &HCL::PublicKey::GetOwner() const {
  return owner_;
}

void HCL::PublicKey::SetOwner(const std::string &owner) {
  this->owner_ = owner;
}

HCL::Crypto::RSAKey *HCL::PublicKey::ExtractKey() const {
  return new Crypto::RSAKey(modulus_, public_key_);
}
