//
// Created by neodar on 07/04/2020.
//

#pragma clang diagnostic push
#pragma ide diagnostic ignored "hicpp-signed-bitwise"

#include "SHA256.h"
#include "../CryptoHelper.h"

const uint32_t HCL::Crypto::SHA256::round_constants_[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
std::string HCL::Crypto::SHA256::HashData(const std::string &data) {
  uint32_t hash_values[8] = {
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  };
  uint32_t words[64];
  uint32_t bloc_working_variable[8];
  uint32_t temp0, temp1;
  std::string padded_data = PadData(data);
  std::string data_chunk;
  std::string hash;

  for (size_t i = 0; i < padded_data.length(); i += 64) {
    data_chunk = padded_data.substr(i, 64);
    for (uint8_t j = 0; j < 16; ++j) {
      words[j] = ((uint32_t) (uint8_t) data_chunk[j * 4] << 24)
          | ((uint32_t) (uint8_t) data_chunk[j * 4 + 1] << 16)
          | ((uint32_t) (uint8_t) data_chunk[j * 4 + 2] << 8)
          | ((uint32_t) (uint8_t) data_chunk[j * 4 + 3]);
    }
    for (uint8_t j = 16; j < 64; ++j) {
      words[j] = words[j - 16] + SHA256_s0(words[j - 15]) + words[j - 7] + SHA256_s1(words[j - 2]);
    }
    for (uint8_t j = 0; j < 8; ++j) {
      bloc_working_variable[j] = hash_values[j];
    }
    for (uint8_t j = 0; j < 64; ++j) {
      temp0 = bloc_working_variable[7]
          + SHA256_S1(bloc_working_variable[4])
          + CH(bloc_working_variable)
          + round_constants_[j]
          + words[j];
      temp1 = SHA256_S0(bloc_working_variable[0]) + MAJ(bloc_working_variable);
      bloc_working_variable[7] = bloc_working_variable[6];
      bloc_working_variable[6] = bloc_working_variable[5];
      bloc_working_variable[5] = bloc_working_variable[4];
      bloc_working_variable[4] = bloc_working_variable[3] + temp0;
      bloc_working_variable[3] = bloc_working_variable[2];
      bloc_working_variable[2] = bloc_working_variable[1];
      bloc_working_variable[1] = bloc_working_variable[0];
      bloc_working_variable[0] = temp0 + temp1;
    }
    for (uint8_t j = 0; j < 8; ++j) {
      hash_values[j] += bloc_working_variable[j];
    }
  }

  for (uint8_t i = 0; i < 8; ++i) {
    hash += (uint8_t) ((hash_values[i] >> 24) & 0xFF);
    hash += (uint8_t) ((hash_values[i] >> 16) & 0xFF);
    hash += (uint8_t) ((hash_values[i] >> 8) & 0xFF);
    hash += (uint8_t) (hash_values[i] & 0xFF);
  }

  return hash;
}

size_t HCL::Crypto::SHA256::GetBlocSize() {
  return 64;
}

std::string HCL::Crypto::SHA256::PadData(const std::string &data) {
  std::string padded_data = data + (char) (0x01 << 7);
  uint64_t data_length = data.length() * 8;

  while ((padded_data.length() + 8) % 64 != 0) {
    padded_data += (char) 0x00;
  }
  padded_data += (uint8_t) ((data_length >> 56) & 0xFF);
  padded_data += (uint8_t) ((data_length >> 48) & 0xFF);
  padded_data += (uint8_t) ((data_length >> 40) & 0xFF);
  padded_data += (uint8_t) ((data_length >> 32) & 0xFF);
  padded_data += (uint8_t) ((data_length >> 24) & 0xFF);
  padded_data += (uint8_t) ((data_length >> 16) & 0xFF);
  padded_data += (uint8_t) ((data_length >> 8) & 0xFF);
  padded_data += (uint8_t) (data_length & 0xFF);

  return padded_data;
}

#pragma clang diagnostic pop
