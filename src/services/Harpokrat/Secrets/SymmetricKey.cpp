//
// Created by neodar on 07/09/2020.
//

#include "SymmetricKey.h"

const std::string &HCL::SymmetricKey::GetOwner() const {
  return owner_;
}

void HCL::SymmetricKey::SetOwner(const std::string &owner) {
  owner_ = owner;
}

const std::string &HCL::SymmetricKey::GetKey() const {
  return key_;
}

void HCL::SymmetricKey::SetKey(const std::string &key) {
  key_ = key;
}

bool HCL::SymmetricKey::DeserializeContent(const std::string &content) {
  const auto *serialized_header = reinterpret_cast<const SerializedSymmetricKeyHeader *>(content.c_str());
  size_t offset = 4;
  size_t serialized_length = offset
      + serialized_header->fields_sizes[0]
      + serialized_header->fields_sizes[1];

  if (content.size() == serialized_length) {
    owner_ = content.substr(offset, serialized_header->fields_sizes[0]);
    offset += serialized_header->fields_sizes[0];
    key_ = content.substr(offset, serialized_header->fields_sizes[1]);
    return false;
  } else {
    return true;
  }
}

std::string HCL::SymmetricKey::SerializeContent() const {
  std::string serialized_content;
  SerializedSymmetricKeyHeader serialized_header{};

  serialized_header.fields_sizes[0] = owner_.size();
  serialized_header.fields_sizes[1] = key_.size();
  serialized_content += std::string(serialized_header.bytes, 4);
  serialized_content += owner_;
  serialized_content += key_;
  return serialized_content;
}
