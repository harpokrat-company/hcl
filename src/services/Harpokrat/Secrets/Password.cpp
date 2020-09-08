//
// Created by neodar on 06/09/2020.
//

#include "Password.h"

const std::string &HCL::Password::GetName() const {
  return name_;
}

const std::string &HCL::Password::GetLogin() const {
  return login_;
}

const std::string &HCL::Password::GetPassword() const {
  return password_;
}

const std::string &HCL::Password::GetDomain() const {
  return domain_;
}

void HCL::Password::SetName(const std::string &name) {
  name_ = name;
}

void HCL::Password::SetLogin(const std::string &login) {
  login_ = login;
}

void HCL::Password::SetPassword(const std::string &password) {
  password_ = password;
}

void HCL::Password::SetDomain(const std::string &domain) {
  domain_ = domain;
}

bool HCL::Password::DeserializeContent(const std::string &content) {
  const auto *serialized_header = reinterpret_cast<const SerializedPasswordHeader *>(content.c_str());
  size_t offset = 8;
  size_t serialized_length = offset
      + serialized_header->fields_sizes[0]
      + serialized_header->fields_sizes[1]
      + serialized_header->fields_sizes[2]
      + serialized_header->fields_sizes[3];

  // TODO Check correct password before decryption with checksum (look at android backup method)
  if (content.size() == serialized_length) {
    name_ = content.substr(offset, serialized_header->fields_sizes[0]);
    offset += serialized_header->fields_sizes[0];
    login_ = content.substr(offset, serialized_header->fields_sizes[1]);
    offset += serialized_header->fields_sizes[1];
    password_ = content.substr(offset, serialized_header->fields_sizes[2]);
    offset += serialized_header->fields_sizes[2];
    domain_ = content.substr(offset, serialized_header->fields_sizes[3]);
    return false;
  } else {
    return true;
  }
}

std::string HCL::Password::SerializeContent() const {
  std::string serialized_content;
  SerializedPasswordHeader serialized_header{};

  serialized_header.fields_sizes[0] = name_.size();
  serialized_header.fields_sizes[1] = login_.size();
  serialized_header.fields_sizes[2] = password_.size();
  serialized_header.fields_sizes[3] = domain_.size();
  serialized_content += std::string(serialized_header.bytes, 8);
  serialized_content += name_;
  serialized_content += login_;
  serialized_content += password_;
  serialized_content += domain_;
  return serialized_content;
}
