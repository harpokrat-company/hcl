//
// Created by neodar on 12/01/2020.
//

#include "Secret.h"
#include "../Crypto/Base64.h"

HCL::Secret::Secret(const std::string &raw_content) {
    Deserialize(raw_content);
}

void HCL::Secret::Deserialize(const std::string &base64_content) {
    std::string serialized_content = HCL::Crypto::Base64::Decode(base64_content); // TODO Decrypt here ?
    const auto *serialized_header = reinterpret_cast<const SerializedSecretHeader *>(serialized_content.c_str());
    uint32_t offset = 8;

    if (serialized_content.size() > 8) {
        this->name_ = serialized_content.substr(offset, serialized_header->fields_sizes[0]);
        offset += serialized_header->fields_sizes[0];
        this->login_ = serialized_content.substr(offset, serialized_header->fields_sizes[1]);
        offset += serialized_header->fields_sizes[1];
        this->password_ = serialized_content.substr(offset, serialized_header->fields_sizes[2]);
        offset += serialized_header->fields_sizes[2];
        this->domain_ = serialized_content.substr(offset, serialized_header->fields_sizes[3]);
    }
}

std::string HCL::Secret::Serialize() const {
    std::string serialized_content;
    SerializedSecretHeader serialized_header{};

    serialized_header.fields_sizes[0] = this->name_.size();
    serialized_header.fields_sizes[1] = this->login_.size();
    serialized_header.fields_sizes[2] = this->password_.size();
    serialized_header.fields_sizes[3] = this->domain_.size();
    serialized_content += std::string(serialized_header.bytes, 8);
    serialized_content += this->name_;
    serialized_content += this->login_;
    serialized_content += this->password_;
    serialized_content += this->domain_;

    return HCL::Crypto::Base64::Encode(serialized_content);
}

const std::string &HCL::Secret::GetName() const {
    return this->name_;
}

const std::string &HCL::Secret::GetLogin() const {
    return this->login_;
}

const std::string &HCL::Secret::GetPassword() const {
    return this->password_;
}

const std::string &HCL::Secret::GetDomain() const {
    return this->domain_;
}

void HCL::Secret::SetName(const std::string &name) {
    this->name_ = name;
}

void HCL::Secret::SetLogin(const std::string &login) {
    this->login_ = login;
}

void HCL::Secret::SetPassword(const std::string &password) {
    this->password_ = password;
}

void HCL::Secret::SetDomain(const std::string &domain) {
    this->domain_ = domain;
}
