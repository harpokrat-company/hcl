//
// Created by neodar on 06/04/2020.
//

#include "ECB.h"
#include "../CryptoHelper.h"

HCL::Crypto::ECB::ECB(const std::string &header, size_t &header_length) :
    ABlockCipherMode(header, header_length),
    APaddedCipher(header, header_length) {}

std::string HCL::Crypto::ECB::Encrypt(const std::string &key, const std::string &content) {
  if (!cipher_) {
    throw std::runtime_error(AutoRegisterer::GetDependencyUnsetError("encrypt", "Cipher"));
  }
  if (!padding_) {
    throw std::runtime_error(AutoRegisterer::GetDependencyUnsetError("encrypt", "Padding"));
  }
  size_t block_size = cipher_->GetBlockSize();
  size_t content_size = content.length();
  std::string prepared_key = cipher_->PrepareKey(key);
  std::string cipher_text;
  size_t index = 0;

  while (index < (content_size - (content_size % block_size) + block_size)) {
    cipher_text += cipher_->EncryptBloc(
        prepared_key,
        padding_->PadDataToSize(content.substr(index, block_size), block_size)
    );
    index += block_size;
  }
  return cipher_text;
}

std::string HCL::Crypto::ECB::Decrypt(const std::string &key, const std::string &content) {
  if (!cipher_) {
    throw std::runtime_error(AutoRegisterer::GetDependencyUnsetError("encrypt", "Cipher"));
  }
  if (!padding_) {
    throw std::runtime_error(AutoRegisterer::GetDependencyUnsetError("encrypt", "Padding"));
  }
  size_t block_size = cipher_->GetBlockSize();
  std::string prepared_key = cipher_->PrepareKey(key);
  std::string next_plain_bloc;
  std::string plain_text;
  size_t index = 0;

  if (content.length() % block_size != 0) {
    throw std::runtime_error(AutoRegisterer::GetError("decrypt", "Size of blob is not a multiple of the bloc size"));
  }
  while (index < content.length()) {
    next_plain_bloc = cipher_->DecryptBloc(prepared_key, content.substr(index, block_size));
    index += block_size;
    if (index == content.length()) {
      next_plain_bloc = padding_->RemovePadding(next_plain_bloc);
    }
    plain_text += next_plain_bloc;
  }
  return plain_text;
}

std::string HCL::Crypto::ECB::GetHeader() {
  return GetIdBytes()
      + ABlockCipherMode::GetHeader()
      + APaddedCipher::GetHeader();
}
