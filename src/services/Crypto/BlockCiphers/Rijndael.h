//
// Created by neodar on 28/03/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_AES_H_
#define HCL_SRC_SERVICES_CRYPTO_AES_H_

#include <stdexcept>
#include <cstdint>
#include <cstring>
#include <iomanip>

#include "../RijndaelSubstitutionBox.h"
#include "../CryptoHelper.h"
#include "ABlockCipher.h"
#include "../RijndaelKeySchedule.h"
#include "../Factory.h"

namespace HCL::Crypto {

template<uint8_t KeySize, uint8_t Rounds>
class Rijndael : virtual public ABlockCipher {
 public:
  Rijndael() = default;
  Rijndael(const std::string &header, size_t &header_length) {
    key_stretching_function_ = Factory<AKeyStretchingFunction>::BuildTypedFromHeader(header, header_length);
  };
  virtual ~Rijndael() = default;
  const std::vector<std::string> &GetDependenciesTypes() override {
    static const std::vector<std::string> dependencies(
        {
            AKeyStretchingFunction::GetName(),
        });
    return dependencies;
  }
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
    if (index >= 1) {
      throw std::runtime_error(GetDependencyIndexError("set"));
    }
    switch (index) {
      case 0:
      default:SetKeyStretchingFunction(std::move(dependency));
    }
  }
  bool IsDependencySet(size_t index) override {
    if (index >= 1) {
      throw std::runtime_error(GetDependencyIndexError("check"));
    }
    switch (index) {
      case 0:
      default:return IsKeyStretchingFunctionSet();
    }
  }
  ACryptoElement &GetDependency(size_t index) override {
    if (index >= 1) {
      throw std::runtime_error(GetDependencyIndexError("get"));
    }
    switch (index) {
      case 0:
      default:return GetKeyStretchingFunction();
    }
  }
  std::string EncryptBloc(const std::string &key, const std::string &bloc) override;
  std::string DecryptBloc(const std::string &key, const std::string &bloc) override;
  size_t GetBlockSize() override
  __attribute__((const));
  std::string PrepareKey(const std::string &key) override
  __attribute__((const));
  void SetKeyStretchingFunction(std::unique_ptr<ACryptoElement> key_stretching_function);
  bool IsKeyStretchingFunctionSet() const;
  ACryptoElement &GetKeyStretchingFunction() const;
 protected:
  std::unique_ptr<AKeyStretchingFunction> key_stretching_function_;
 private:
  static void EncryptArrayBloc(const uint8_t[KeySize], uint8_t [16]);
  static void DecryptArrayBloc(const uint8_t[KeySize], uint8_t [16]);
  static void AddRoundKey(uint8_t [4][4], const uint8_t [16]);
  static void SubBytes(uint8_t [4][4]);
  static void ShiftRows(uint8_t [4][4]);
  static uint8_t GaloisProduct(uint8_t, uint8_t);
  static uint8_t GaloisColumnProduct(const uint8_t [4], const uint8_t [4]);
  static void MixColumn(uint8_t [4][4], uint8_t);
  static void MixColumns(uint8_t [4][4]);
  static void InvSubBytes(uint8_t [4][4]);
  static void InvShiftRows(uint8_t [4][4]);
  static void InvMixColumn(uint8_t [4][4], uint8_t);
  static void InvMixColumns(uint8_t [4][4]);
  static void BlocToState(const uint8_t [16], uint8_t [4][4]);
  static void StateToBloc(const uint8_t [4][4], uint8_t [16]);
  static void EncryptState(const uint8_t[KeySize], uint8_t [4][4]);
  static void DecryptState(const uint8_t[KeySize], uint8_t [4][4]);
};

template<uint8_t KeySize, uint8_t Rounds>
void Rijndael<KeySize, Rounds>::AddRoundKey(uint8_t state[4][4], const uint8_t round_key[16]) {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      state[j][i] ^= round_key[i * 4 + j];
    }
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void Rijndael<KeySize, Rounds>::SubBytes(uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    RijndaelSubstitutionBox::SubWord(state[i], state[i]);
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void Rijndael<KeySize, Rounds>::InvSubBytes(uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    RijndaelSubstitutionBox::InvSubWord(state[i], state[i]);
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void Rijndael<KeySize, Rounds>::ShiftRows(uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    for (int _ = 0; _ < i; ++_) {
      CryptoHelper::RotWord(state[i], state[i]);
    }
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void Rijndael<KeySize, Rounds>::InvShiftRows(uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    for (int _ = 0; _ < i; ++_) {
      CryptoHelper::InvRotWord(state[i], state[i]);
    }
  }
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "hicpp-signed-bitwise"
template<uint8_t KeySize, uint8_t Rounds>
uint8_t Rijndael<KeySize, Rounds>::GaloisProduct(uint8_t a, uint8_t b) {
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
uint8_t Rijndael<KeySize, Rounds>::GaloisColumnProduct(const uint8_t coefficient[4],
                                                       const uint8_t column[4]) {
  uint8_t product = 0;

  for (int i = 0; i < 4; ++i) {
    product ^= GaloisProduct(coefficient[i], column[i]);
  }
  return product;
}

template<uint8_t KeySize, uint8_t Rounds>
void Rijndael<KeySize, Rounds>::MixColumn(uint8_t state[4][4], uint8_t column_index) {
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
void Rijndael<KeySize, Rounds>::MixColumns(uint8_t state[4][4]) {
  for (int column_index = 0; column_index < 4; ++column_index) {
    MixColumn(state, column_index);
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void Rijndael<KeySize, Rounds>::InvMixColumn(uint8_t state[4][4], uint8_t column_index) {
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
void Rijndael<KeySize, Rounds>::InvMixColumns(uint8_t state[4][4]) {
  for (int column_index = 0; column_index < 4; ++column_index) {
    InvMixColumn(state, column_index);
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void Rijndael<KeySize, Rounds>::BlocToState(const uint8_t data[16], uint8_t state[4][4]) {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      state[j][i] = data[i * 4 + j];
    }
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void Rijndael<KeySize, Rounds>::StateToBloc(const uint8_t state[4][4], uint8_t data[16]) {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      data[i * 4 + j] = state[j][i];
    }
  }
}

template<uint8_t KeySize, uint8_t Rounds>
void Rijndael<KeySize, Rounds>::EncryptState(const uint8_t key[KeySize], uint8_t state[4][4]) {
  uint8_t round_keys[Rounds + 1][16] = {};

  RijndaelKeySchedule::KeyExpansion<KeySize, Rounds + 1>(key, round_keys);
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
void Rijndael<KeySize, Rounds>::DecryptState(const uint8_t key[KeySize], uint8_t state[4][4]) {
  uint8_t round_keys[Rounds + 1][16] = {};

  RijndaelKeySchedule::KeyExpansion<KeySize, Rounds + 1>(key, round_keys);
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
void Rijndael<KeySize, Rounds>::EncryptArrayBloc(const uint8_t key[KeySize], uint8_t data[16]) {
  uint8_t state[4][4];

  BlocToState(data, state);
  EncryptState(key, state);
  StateToBloc(state, data);
}

template<uint8_t KeySize, uint8_t Rounds>
void Rijndael<KeySize, Rounds>::DecryptArrayBloc(const uint8_t key[KeySize], uint8_t data[16]) {
  uint8_t state[4][4];

  BlocToState(data, state);
  DecryptState(key, state);
  StateToBloc(state, data);
}

template<uint8_t KeySize, uint8_t Rounds>
std::string Rijndael<KeySize, Rounds>::EncryptBloc(const std::string &key, const std::string &bloc) {
  char data[16];

  for (int i = 0; i < 16; ++i) {
    data[i] = bloc[i];
  }
  EncryptArrayBloc((uint8_t *) key.c_str(), (uint8_t *) data);
  return std::string(data, 16);
}

template<uint8_t KeySize, uint8_t Rounds>
std::string Rijndael<KeySize, Rounds>::DecryptBloc(const std::string &key, const std::string &bloc) {
  char data[16];

  for (int i = 0; i < 16; ++i) {
    data[i] = bloc[i];
  }
  DecryptArrayBloc((uint8_t *) key.c_str(), (uint8_t *) data);
  return std::string(data, 16);
}

template<uint8_t KeySize, uint8_t Rounds>
size_t Rijndael<KeySize, Rounds>::GetBlockSize() {
  return 16;
}

template<uint8_t KeySize, uint8_t Rounds>
std::string Rijndael<KeySize, Rounds>::PrepareKey(const std::string &key) {
  if (!key_stretching_function_) {
    throw std::runtime_error(GetDependencyUnsetError("prepare key", "Key stretching function"));
  }
  return key_stretching_function_->StretchKey(key, KeySize);
}

template<uint8_t KeySize, uint8_t Rounds>
void Rijndael<KeySize, Rounds>::SetKeyStretchingFunction(std::unique_ptr<ACryptoElement> key_stretching_function) {
  key_stretching_function_ = ACryptoElement::UniqueTo<AKeyStretchingFunction>(std::move(key_stretching_function));
}

template<uint8_t KeySize, uint8_t Rounds>
bool Rijndael<KeySize, Rounds>::IsKeyStretchingFunctionSet() const {
  return !!key_stretching_function_;
}

template<uint8_t KeySize, uint8_t Rounds>
ACryptoElement &Rijndael<KeySize, Rounds>::GetKeyStretchingFunction() const {
  if (!IsKeyStretchingFunctionSet()) {
    throw std::runtime_error(GetDependencyUnsetError("get Key stretching function", "Key stretching function"));
  }
  return *key_stretching_function_;
}
}
#endif //HCL_SRC_SERVICES_CRYPTO_AES_H_
