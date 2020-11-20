//
// Created by neodar on 06/04/2020.
//

#include "PlainCipherScheme.h"
#include "../../Harpokrat/Secrets/SymmetricKey.h"

HCL::Crypto::PlainCipherScheme::PlainCipherScheme(const std::string &header, size_t &header_length) {}

std::string HCL::Crypto::PlainCipherScheme::Encrypt(const ICipherEncryptionKey *password, const std::string &content) {
  return content;
}

std::string HCL::Crypto::PlainCipherScheme::Decrypt(const ICipherDecryptionKey *password, const std::string &content) {
  return content;
}

std::string HCL::Crypto::PlainCipherScheme::GetHeader() {
  return GetIdBytes();
}
