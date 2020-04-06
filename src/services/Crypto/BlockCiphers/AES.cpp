//
// Created by neodar on 28/03/2020.
//

#include <iostream>
#include <iomanip>

#include "AES.h"
#include "../RijndaelKeySchedule.h"

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

void HCL::Crypto::AES::InvSubBytes(uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    HCL::Crypto::RijndaelSubstitutionBox::InvSubWord(state[i], state[i]);
  }
}

void HCL::Crypto::AES::ShiftRows(uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    for (int _ = 0; _ < i; ++_) {
      HCL::Crypto::CryptoHelper::RotWord(state[i], state[i]);
    }
  }
}

void HCL::Crypto::AES::InvShiftRows(uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    for (int _ = 0; _ < i; ++_) {
      HCL::Crypto::CryptoHelper::InvRotWord(state[i], state[i]);
    }
  }
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "hicpp-signed-bitwise"
uint8_t HCL::Crypto::AES::GaloisProduct(uint8_t a, uint8_t b) {
  bool high_bit_set;
  uint8_t product = 0;

  for (int i = 0; i < 8; ++i) {
    if ((b & 1) != 0) {
      product ^= a;
    }
    high_bit_set = (a & 0x80) != 0;
    a <<= 1;
    if (high_bit_set) {
      a ^= 0x1B;
    }
    b >>= 1;
  }

  return product;
}
#pragma clang diagnostic pop

uint8_t HCL::Crypto::AES::GaloisColumnProduct(const uint8_t coefficient[4], const uint8_t column[4]) {
  uint8_t product = 0;

  for (int i = 0; i < 4; ++i) {
    product ^= GaloisProduct(coefficient[i], column[i]);
  }
  return product;
}

void HCL::Crypto::AES::MixColumn(uint8_t state[4][4], uint8_t column_index) {
  const uint8_t coefficients[4][4] = {
      {2, 3, 1, 1},
      {1, 2, 3, 1},
      {1, 1, 2, 3},
      {3, 1, 1, 2}
  };
  uint8_t old_column[4];

  for (int i = 0; i < 4; ++i) {
    old_column[i] = state[i][column_index];
  }
  for (int i = 0; i < 4; ++i) {
    state[i][column_index] = GaloisColumnProduct(coefficients[i], old_column);
  }
}

void HCL::Crypto::AES::MixColumns(uint8_t state[4][4]) {
  for (int column_index = 0; column_index < 4; ++column_index) {
    MixColumn(state, column_index);
  }
}
void HCL::Crypto::AES::InvMixColumn(uint8_t state[4][4], uint8_t column_index) {
  const uint8_t coefficients[4][4] = {
      {14, 11, 13, 9},
      {9, 14, 11, 13},
      {13, 9, 14, 11},
      {11, 13, 9, 14}
  };
  uint8_t old_column[4];

  for (int i = 0; i < 4; ++i) {
    old_column[i] = state[i][column_index];
  }
  for (int i = 0; i < 4; ++i) {
    state[i][column_index] = GaloisColumnProduct(coefficients[i], old_column);
  }
}

void HCL::Crypto::AES::InvMixColumns(uint8_t state[4][4]) {
  for (int column_index = 0; column_index < 4; ++column_index) {
    InvMixColumn(state, column_index);
  }
}

void HCL::Crypto::AES::BlocToState(const uint8_t data[16], uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      state[j][i] = data[i * 4 + j];
    }
  }
}

void HCL::Crypto::AES::StateToBloc(const uint8_t state[4][4], uint8_t data[16]) {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      data[i * 4 + j] = state[j][i];
    }
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::AES::EncryptState(const uint8_t key[KeySize], uint8_t state[4][4]) {
  uint8_t round_keys[Rounds + 1][16] = {};

  HCL::Crypto::RijndaelKeySchedule::KeyExpansion<KeySize, Rounds + 1>(key, round_keys);
  AddRoundKey(state, round_keys[0]);
  for (int i = 0; i < Rounds - 1; ++i) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, round_keys[i + 1]);
  }
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, round_keys[Rounds]);
}

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::AES::EncryptBloc(const uint8_t key[KeySize], uint8_t data[16]) {
  uint8_t state[4][4];

  BlocToState(data, state);
  EncryptState<KeySize, Rounds>(key, state);
  StateToBloc(state, data);
}

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::AES::DecryptState(const uint8_t key[KeySize], uint8_t state[4][4]) {
  uint8_t round_keys[Rounds + 1][16] = {};

  HCL::Crypto::RijndaelKeySchedule::KeyExpansion<KeySize, Rounds + 1>(key, round_keys);
  AddRoundKey(state, round_keys[Rounds]);
  for (int i = Rounds - 1; i >= 0; --i) {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, round_keys[i]);
    if (i != 0) {
      InvMixColumns(state);
    }
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::AES::DecryptBloc(const uint8_t key[KeySize], uint8_t data[16]) {
  uint8_t state[4][4];

  BlocToState(data, state);
  DecryptState<KeySize, Rounds>(key, state);
  StateToBloc(state, data);
}

void HCL::Crypto::AES::AES128Encrypt(const uint8_t key[16], uint8_t data[16]) {
  EncryptBloc<16, 10>(key, data);
}

void HCL::Crypto::AES::AES192Encrypt(const uint8_t key[24], uint8_t data[16]) {
  EncryptBloc<24, 12>(key, data);
}

void HCL::Crypto::AES::AES256Encrypt(const uint8_t key[32], uint8_t data[16]) {
  EncryptBloc<32, 14>(key, data);
}

void HCL::Crypto::AES::AES128Decrypt(const uint8_t key[16], uint8_t data[16]) {
  DecryptBloc<16, 10>(key, data);
}

void HCL::Crypto::AES::AES192Decrypt(const uint8_t key[24], uint8_t data[16]) {
  DecryptBloc<24, 12>(key, data);
}

void HCL::Crypto::AES::AES256Decrypt(const uint8_t key[32], uint8_t data[16]) {
  DecryptBloc<32, 14>(key, data);
}
