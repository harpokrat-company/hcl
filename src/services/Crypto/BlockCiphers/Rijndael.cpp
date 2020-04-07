//
// Created by neodar on 28/03/2020.
//

#include <cstring>

#include "Rijndael.h"
#include "../RijndaelKeySchedule.h"

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::Rijndael<KeySize, Rounds>::AddRoundKey(uint8_t state[4][4], const uint8_t round_key[16]) {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      state[j][i] ^= round_key[i * 4 + j];
    }
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::Rijndael<KeySize, Rounds>::SubBytes(uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    HCL::Crypto::RijndaelSubstitutionBox::SubWord(state[i], state[i]);
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::Rijndael<KeySize, Rounds>::InvSubBytes(uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    HCL::Crypto::RijndaelSubstitutionBox::InvSubWord(state[i], state[i]);
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::Rijndael<KeySize, Rounds>::ShiftRows(uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    for (int _ = 0; _ < i; ++_) {
      HCL::Crypto::CryptoHelper::RotWord(state[i], state[i]);
    }
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::Rijndael<KeySize, Rounds>::InvShiftRows(uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    for (int _ = 0; _ < i; ++_) {
      HCL::Crypto::CryptoHelper::InvRotWord(state[i], state[i]);
    }
  }
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "hicpp-signed-bitwise"
template<uint8_t KeySize, uint8_t Rounds>
uint8_t HCL::Crypto::Rijndael<KeySize, Rounds>::GaloisProduct(uint8_t a, uint8_t b) {
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

template<uint8_t KeySize, uint8_t Rounds>
uint8_t HCL::Crypto::Rijndael<KeySize, Rounds>::GaloisColumnProduct(const uint8_t coefficient[4],
                                                                    const uint8_t column[4]) {
  uint8_t product = 0;

  for (int i = 0; i < 4; ++i) {
    product ^= GaloisProduct(coefficient[i], column[i]);
  }
  return product;
}

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::Rijndael<KeySize, Rounds>::MixColumn(uint8_t state[4][4], uint8_t column_index) {
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

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::Rijndael<KeySize, Rounds>::MixColumns(uint8_t state[4][4]) {
  for (int column_index = 0; column_index < 4; ++column_index) {
    MixColumn(state, column_index);
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::Rijndael<KeySize, Rounds>::InvMixColumn(uint8_t state[4][4], uint8_t column_index) {
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

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::Rijndael<KeySize, Rounds>::InvMixColumns(uint8_t state[4][4]) {
  for (int column_index = 0; column_index < 4; ++column_index) {
    InvMixColumn(state, column_index);
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::Rijndael<KeySize, Rounds>::BlocToState(const uint8_t data[16], uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      state[j][i] = data[i * 4 + j];
    }
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::Rijndael<KeySize, Rounds>::StateToBloc(const uint8_t state[4][4], uint8_t data[16]) {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      data[i * 4 + j] = state[j][i];
    }
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::Rijndael<KeySize, Rounds>::EncryptState(const uint8_t key[KeySize], uint8_t state[4][4]) {
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
void HCL::Crypto::Rijndael<KeySize, Rounds>::DecryptState(const uint8_t key[KeySize], uint8_t state[4][4]) {
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
void HCL::Crypto::Rijndael<KeySize, Rounds>::EncryptArrayBloc(const uint8_t key[KeySize], uint8_t data[16]) {
  uint8_t state[4][4];

  BlocToState(data, state);
  EncryptState(key, state);
  StateToBloc(state, data);
}

template<uint8_t KeySize, uint8_t Rounds>
void HCL::Crypto::Rijndael<KeySize, Rounds>::DecryptArrayBloc(const uint8_t key[KeySize], uint8_t data[16]) {
  uint8_t state[4][4];

  BlocToState(data, state);
  DecryptState(key, state);
  StateToBloc(state, data);
}

template<uint8_t KeySize, uint8_t Rounds>
std::string HCL::Crypto::Rijndael<KeySize, Rounds>::EncryptBloc(const std::string &key, const std::string &bloc) {
  char data[16];

  std::strcpy(data, bloc.c_str());
  EncryptArrayBloc((uint8_t *) key.c_str(), (uint8_t *) data);
  return std::string(data, 16);
}

template<uint8_t KeySize, uint8_t Rounds>
std::string HCL::Crypto::Rijndael<KeySize, Rounds>::DecryptBloc(const std::string &key, const std::string &bloc) {
  char data[16];

  std::strcpy(data, bloc.c_str());
  DecryptArrayBloc((uint8_t *) key.c_str(), (uint8_t *) data);
  return std::string(data, 16);
}

template<uint8_t KeySize, uint8_t Rounds>
size_t HCL::Crypto::Rijndael<KeySize, Rounds>::GetBlockSize() {
  return 16;
}

template<uint8_t KeySize, uint8_t Rounds>
std::string HCL::Crypto::Rijndael<KeySize, Rounds>::PrepareKey(const std::string &key) {
  return key_stretching_->StretchKey(key, KeySize);
}
