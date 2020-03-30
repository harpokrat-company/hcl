//
// Created by neodar on 28/03/2020.
//

#include "AES.h"
#include "RijndaelKeySchedule.h"

void HCL::Crypto::AES::AddRoundKey(uint8_t state[4][4], const uint8_t round_key[16]) {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      state[j][i] ^= round_key[i * 4 + j];
    }
  }
}

void HCL::Crypto::AES::SubBytes(uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    HCL::Crypto::RijndaelSubstitutionBox::SubWord(state[i], state[i]);
  }
}

void HCL::Crypto::AES::ShiftRows(uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    for (int _ = 0; _ < i; ++_) {
      HCL::Crypto::CryptoHelper::RotWord(state[i], state[i]);
    }
  }
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "hicpp-signed-bitwise"
void HCL::Crypto::AES::MixColumn(uint8_t state[4][4], uint8_t column_index) {
  uint8_t old_column[4];
  uint8_t galois_double[4];

  for (int i = 0; i < 4; ++i) {
    old_column[i] = state[i][column_index];
    galois_double[i] = old_column[i] << 1 ^ (0x1b * (old_column[i] >> 7));
  }
  state[0][column_index] = galois_double[0] ^ old_column[3] ^ old_column[2] ^ galois_double[1] ^ old_column[1];
  state[1][column_index] = galois_double[1] ^ old_column[0] ^ old_column[3] ^ galois_double[2] ^ old_column[2];
  state[2][column_index] = galois_double[2] ^ old_column[1] ^ old_column[0] ^ galois_double[3] ^ old_column[3];
  state[3][column_index] = galois_double[3] ^ old_column[2] ^ old_column[1] ^ galois_double[0] ^ old_column[0];
}
#pragma clang diagnostic pop

void HCL::Crypto::AES::MixColumns(uint8_t state[4][4]) {
  for (int column_index = 0; column_index < 4; ++column_index) {
    MixColumn(state, column_index);
  }
}
void HCL::Crypto::AES::AES256(const uint8_t key[32], uint8_t state[4][4]) {
  uint8_t round_keys[15][16] = {};

  // TODO Template for different sizes
  HCL::Crypto::RijndaelKeySchedule::AES256KeyExpansion(key, round_keys);
  AddRoundKey(state, round_keys[0]);
  for (int i = 0; i < 13; ++i) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, round_keys[i + 1]);
  }
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, round_keys[14]);
}
