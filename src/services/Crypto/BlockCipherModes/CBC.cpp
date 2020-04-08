//
// Created by neodar on 06/04/2020.
//

#include "CBC.h"
#include "../CryptoHelper.h"

HCL::Crypto::CBC::CBC(const std::string &header, size_t &header_length) :
    ABlockCipherMode(header, header_length),
    APaddedCipher(header, header_length),
    AInitializationVectorBlockCipherMode(header, header_length) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-value"
  is_registered_;
#pragma GCC diagnostic pop

}

std::string HCL::Crypto::CBC::Encrypt(const std::string &key, const std::string &content) {
  if (!cipher_) {
    throw std::runtime_error("CBC error: Cipher is not set");
  }
  if (!padding_) {
    throw std::runtime_error("CBC error: Padding is not set");
  }
  size_t block_size = cipher_->GetBlockSize();
  size_t content_size = content.length();
  std::string prepared_key = cipher_->PrepareKey(key);
  std::string previous_cipher_bloc = GetInitializationVector(block_size);
  std::string next_plain_bloc;
  std::string cipher_text = previous_cipher_bloc;
  size_t index = 0;

  while (index < (content_size - (content_size % block_size) + block_size)) {
    next_plain_bloc = CryptoHelper::XorStrings(
        padding_->PadDataToSize(content.substr(index, block_size), block_size),
        previous_cipher_bloc);
    previous_cipher_bloc = cipher_->EncryptBloc(prepared_key, next_plain_bloc);
    index += block_size;
    cipher_text += previous_cipher_bloc;
  }
  return cipher_text;
}

std::string HCL::Crypto::CBC::Decrypt(const std::string &key, const std::string &content) {
  if (!cipher_) {
    throw std::runtime_error("CBC error: Cipher is not set");
  }
  if (!padding_) {
    throw std::runtime_error("CBC error: Padding is not set");
  }
  size_t block_size = cipher_->GetBlockSize();
  std::string prepared_key = cipher_->PrepareKey(key);
  std::string next_plain_bloc;
  std::string plain_text;
  size_t index = block_size;

  if (content.length() % block_size != 0) {
    throw std::runtime_error("CBC Decrypt: Incorrect blob: Size not multiple of bloc size");
  }
  while (index < content.length()) {
    next_plain_bloc = CryptoHelper::XorStrings(
        cipher_->DecryptBloc(prepared_key, content.substr(index, block_size)),
        content.substr(index - block_size, block_size));
    index += block_size;
    if (index == content.length()) {
      next_plain_bloc = padding_->RemovePadding(next_plain_bloc);
    }
    plain_text += next_plain_bloc;
  }
  return plain_text;
}

std::string HCL::Crypto::CBC::GetHeader() {
  return GetIdBytes()
      + ABlockCipherMode::GetHeader()
      + APaddedCipher::GetHeader()
      + AInitializationVectorBlockCipherMode::GetHeader();
}
