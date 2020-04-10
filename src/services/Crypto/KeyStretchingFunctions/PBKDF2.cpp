//
// Created by neodar on 07/04/2020.
//

#include "PBKDF2.h"
#include "../Factory.h"

HCL::Crypto::PBKDF2::PBKDF2() : iterations_(PBKDF2_DEFAULT_ITERATIONS) {
}

HCL::Crypto::PBKDF2::PBKDF2(const std::string &header, size_t &header_length) {
  ParseSalt(header, header_length);
  ParseIterations(header, header_length);
  message_authentication_code_ = Factory<AMessageAuthenticationCode>::BuildTypedFromHeader(header, header_length);
}

std::string HCL::Crypto::PBKDF2::StretchKey(const std::string &key, size_t derived_key_length) {
  std::string derived_key;

  for (uint32_t i = 0; derived_key.length() < derived_key_length; ++i) {
    derived_key += GetPBKDF2Bloc(key, i);
  }

  return derived_key.substr(0, derived_key_length);
}

std::string HCL::Crypto::PBKDF2::GetPBKDF2Bloc(const std::string &key, uint32_t bloc_index) {
  if (!message_authentication_code_) {
    throw std::runtime_error("PBKDF2 error: Message authentication code is not set");
  }
  if (!is_salt_set_) {
    if (!random_generator_) {
      throw std::runtime_error("PBKDF2 error: Random generator is not set");
    }
    salt_ = random_generator_->GenerateRandomByteSequence(PBKDF2_DEFAULT_SALT_LENGTH);
    is_salt_set_ = true;
  }
  char serialized_bloc_index[4] = {
      static_cast<char>((bloc_index >> 24) & 0xFF),
      static_cast<char>((bloc_index >> 16) & 0xFF),
      static_cast<char>((bloc_index >> 8) & 0xFF),
      static_cast<char>(bloc_index & 0xFF)
  };
  std::string bloc = message_authentication_code_->SignMessage(key, salt_ + std::string(serialized_bloc_index, 4));

  for (size_t i = 1; i < iterations_; ++i) {
    bloc = message_authentication_code_->SignMessage(key, bloc);
  }

  return bloc;
}

void HCL::Crypto::PBKDF2::ParseSalt(const std::string &header, size_t &header_length) {
  uint16_t salt_length;

  if (header.length() < header_length + 2) {
    throw std::runtime_error("PBKDF2: Impossible to parse salt size: Incorrect blob header: Too short");
  }
  salt_length = uint16_t(((uint8_t) header[header_length]) << 8 | (uint8_t) header[header_length + 1]);
  header_length += 2;
  if (header.length() < header_length + salt_length) {
    throw std::runtime_error("PBKDF2: Impossible to parse salt value: Incorrect blob header: Too short");
  }
  salt_ = header.substr(header_length, salt_length);
  is_salt_set_ = true;
  header_length += salt_length;
}

void HCL::Crypto::PBKDF2::ParseIterations(const std::string &header, size_t &header_length) {
  if (header.length() < header_length + 4) {
    throw std::runtime_error("PBKDF2: Impossible to parse iterations: Incorrect blob header: Too short");
  }
  iterations_ = uint32_t(((uint8_t) header[header_length]) << 24
                             | ((uint8_t) header[header_length + 1]) << 16
                             | ((uint8_t) header[header_length + 2]) << 8
                             | (uint8_t) header[header_length + 3]);
  header_length += 4;
}

std::string HCL::Crypto::PBKDF2::GetHeader() {
  if (!message_authentication_code_) {
    throw std::runtime_error("PBKDF2 error: Message authentication code is not set");
  }
  std::string header = GetIdBytes();

  header += SerializeSalt();
  header += SerializeIterations();
  return header + message_authentication_code_->GetHeader();
}

void HCL::Crypto::PBKDF2::SetMessageAuthenticationCode(std::unique_ptr<ACryptoElement> message_authentication_code) {
  message_authentication_code_ =
      ACryptoElement::UniqueTo<AMessageAuthenticationCode>(std::move(message_authentication_code));
}

void HCL::Crypto::PBKDF2::SetRandomGenerator(std::unique_ptr<ACryptoElement> random_generator) {
  random_generator_ = ACryptoElement::UniqueTo<ARandomGenerator>(std::move(random_generator));
}

std::string HCL::Crypto::PBKDF2::SerializeSalt() {
  if (!is_salt_set_) {
    if (!random_generator_) {
      throw std::runtime_error("PBKDF2 error: Random generator is not set");
    }
    salt_ = random_generator_->GenerateRandomByteSequence(PBKDF2_DEFAULT_SALT_LENGTH);
    is_salt_set_ = true;
  }
  std::string serialized;

  serialized += (uint8_t) ((salt_.length() >> 8) & 0xFF);
  serialized += (uint8_t) (salt_.length() & 0xFF);
  return serialized + salt_;
}

std::string HCL::Crypto::PBKDF2::SerializeIterations() {
  std::string serialized;

  serialized += (uint8_t) ((iterations_ >> 24) & 0xFF);
  serialized += (uint8_t) ((iterations_ >> 16) & 0xFF);
  serialized += (uint8_t) ((iterations_ >> 8) & 0xFF);
  serialized += (uint8_t) (iterations_ & 0xFF);
  return serialized;
}
