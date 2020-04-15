//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_SHA2_H_
#define HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_SHA2_H_

#include "AHashFunction.h"

namespace HCL::Crypto {

#define IS_64(x)  (sizeof(x) > 4)

#define RIGHT_SHIFT(x, n)   ((x) >> (n))
#define RIGHT_ROTATE(x, n)  (((x) >> (n)) | ((x) << ((sizeof(x) << 3) - (n))))
#define CH(x)               (((x)[4] & (x)[5]) ^ ((~((x)[4])) & (x)[6]))
#define MAJ(x)              (((x)[0] & (x)[1]) ^ ((x)[0] & (x)[2]) ^ ((x)[1] & (x)[2]))

#define SHA2_S0_32(x)        (RIGHT_ROTATE(x,  2) ^ RIGHT_ROTATE(x, 13) ^ RIGHT_ROTATE(x, 22))
#define SHA2_S1_32(x)        (RIGHT_ROTATE(x,  6) ^ RIGHT_ROTATE(x, 11) ^ RIGHT_ROTATE(x, 25))
#define SHA2_s0_32(x)        (RIGHT_ROTATE(x,  7) ^ RIGHT_ROTATE(x, 18) ^ RIGHT_SHIFT(x,  3))
#define SHA2_s1_32(x)        (RIGHT_ROTATE(x, 17) ^ RIGHT_ROTATE(x, 19) ^ RIGHT_SHIFT(x, 10))

#define SHA2_S0_64(x)        (RIGHT_ROTATE(x,  28) ^ RIGHT_ROTATE(x, 34) ^ RIGHT_ROTATE(x, 39))
#define SHA2_S1_64(x)        (RIGHT_ROTATE(x,  14) ^ RIGHT_ROTATE(x, 18) ^ RIGHT_ROTATE(x, 41))
#define SHA2_s0_64(x)        (RIGHT_ROTATE(x,  1) ^ RIGHT_ROTATE(x, 8) ^ RIGHT_SHIFT(x,  7))
#define SHA2_s1_64(x)        (RIGHT_ROTATE(x, 19) ^ RIGHT_ROTATE(x, 61) ^ RIGHT_SHIFT(x, 6))

#define SHA2_S0(x)  (IS_64(x) ? (SHA2_S0_64(x)) : (SHA2_S0_32(x)))
#define SHA2_S1(x)  (IS_64(x) ? (SHA2_S1_64(x)) : (SHA2_S1_32(x)))
#define SHA2_s0(x)  (IS_64(x) ? (SHA2_s0_64(x)) : (SHA2_s0_32(x)))
#define SHA2_s1(x)  (IS_64(x) ? (SHA2_s1_64(x)) : (SHA2_s1_32(x)))

#define DESERIALIZE_32(s, idx, x)                 \
  (x) = (((uint32_t) (uint8_t) (s)[(idx)] << 24))     \
      | (((uint32_t) (uint8_t) (s)[(idx) + 1] << 16)) \
      | (((uint32_t) (uint8_t) (s)[(idx) + 2] << 8))  \
      | (((uint32_t) (uint8_t) (s)[(idx) + 3]));

#define DESERIALIZE_64(s, idx, x)                 \
  (x) = (((uint64_t) (uint8_t) (s)[(idx)] << 56))     \
      | (((uint64_t) (uint8_t) (s)[(idx) + 1] << 48)) \
      | (((uint64_t) (uint8_t) (s)[(idx) + 2] << 40)) \
      | (((uint64_t) (uint8_t) (s)[(idx) + 3] << 32)) \
      | (((uint64_t) (uint8_t) (s)[(idx) + 4] << 24)) \
      | (((uint64_t) (uint8_t) (s)[(idx) + 5] << 16)) \
      | (((uint64_t) (uint8_t) (s)[(idx) + 6] << 8))  \
      | (((uint64_t) (uint8_t) (s)[(idx) + 7]));

#define DESERIALIZE(s, idx, x)    \
  if (IS_64(x)){                  \
    DESERIALIZE_64(s, idx, x)     \
  } else {                        \
    DESERIALIZE_32(s, idx, x)     \
  }

#define SERIALIZE_32(s, x)                \
  (s) += (uint8_t) (((x) >> 24) & 0xFF);  \
  (s) += (uint8_t) (((x) >> 16) & 0xFF);  \
  (s) += (uint8_t) (((x) >> 8) & 0xFF);   \
  (s) += (uint8_t) ((x)& 0xFF);

#define SERIALIZE_64(s, x)                \
  (s) += (uint8_t) (((x) >> 56) & 0xFF);  \
  (s) += (uint8_t) (((x) >> 48) & 0xFF);  \
  (s) += (uint8_t) (((x) >> 40) & 0xFF);  \
  (s) += (uint8_t) (((x) >> 32) & 0xFF);  \
  SERIALIZE_32(s, x)

#define SERIALIZE(s, x)    \
  if (IS_64(x)){           \
    SERIALIZE_64(s, x)     \
  } else {                 \
    SERIALIZE_32(s, x)     \
  }

// TODO Optimize whole algorithm
//  -> use fixed size char array instead of strings ?
template<typename WordType>
class SHA2 : virtual public AHashFunction {
 public:
  SHA2() = default;
  ~SHA2() override = default;
  std::string HashData(const std::string &data) override;
  const std::vector<std::string> &GetDependenciesTypes() override {
    static const std::vector<std::string> dependencies({});
    return dependencies;
  }
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
    throw std::runtime_error("SHA2 error: Cannot set dependency: Incorrect dependency index");
  }
  bool IsDependencySet(size_t index) override {
    throw std::runtime_error("SHA2 error: Cannot check dependency: Incorrect dependency index");
  }
  ACryptoElement &GetDependency(size_t index) override {
    throw std::runtime_error("SHA2 error: Cannot get dependency: Incorrect dependency index");
  }
 protected:
  virtual WordType GetHashValue(size_t index) const = 0;
  virtual WordType GetRoundConstant(size_t index) const = 0;
  virtual uint8_t GetOutputSize() const = 0;
  virtual uint8_t GetRoundsNbr() const = 0;
 private:
  std::string PadData(const std::string &data);
};

#pragma clang diagnostic push
#pragma ide diagnostic ignored "hicpp-signed-bitwise"

template <typename WordType>
std::string HCL::Crypto::SHA2<WordType>::HashData(const std::string &data) {
  WordType words[GetRoundsNbr()];
  WordType hash_values[8];
  WordType bloc_var[8];
  WordType temp0, temp1;
  std::string padded_data = PadData(data);
  std::string data_chunk;
  std::string hash;
  size_t i;
  uint8_t j;

  for (j = 0; j < 8; ++j) {
    hash_values[j] = GetHashValue(j);
  }
  for (i = 0; i < padded_data.length(); i += GetBlocSize()) {
    data_chunk = padded_data.substr(i, GetBlocSize());
    for (j = 0; j < 16; ++j) {
      DESERIALIZE(data_chunk, j * sizeof(WordType), words[j])
    }
    for (j = 16; j < GetRoundsNbr(); ++j) {
      words[j] = words[j - 16] + SHA2_s0(words[j - 15]) + words[j - 7] + SHA2_s1(words[j - 2]);
    }
    for (j = 0; j < 8; ++j) {
      bloc_var[j] = hash_values[j];
    }
    for (j = 0; j < GetRoundsNbr(); ++j) {
      temp0 = bloc_var[7] + SHA2_S1(bloc_var[4]) + CH(bloc_var) + GetRoundConstant(j) + words[j];
      temp1 = SHA2_S0(bloc_var[0]) + MAJ(bloc_var);
      bloc_var[7] = bloc_var[6];
      bloc_var[6] = bloc_var[5];
      bloc_var[5] = bloc_var[4];
      bloc_var[4] = bloc_var[3] + temp0;
      bloc_var[3] = bloc_var[2];
      bloc_var[2] = bloc_var[1];
      bloc_var[1] = bloc_var[0];
      bloc_var[0] = temp0 + temp1;
    }
    for (j = 0; j < 8; ++j) {
      hash_values[j] += bloc_var[j];
    }
  }

  for (j = 0; j < 8; ++j) {
    SERIALIZE(hash, hash_values[j])
  }

  return hash.substr(0, GetOutputSize());
}

template <typename WordType>
std::string HCL::Crypto::SHA2<WordType>::PadData(const std::string &data) {
  std::string padded_data = data + (char) (0x01 << 7);
  uint64_t data_length = data.length() * 8;

  while ((padded_data.length() + sizeof(WordType) * 2) % GetBlocSize() != 0) {
    padded_data += (char) 0x00;
  }

  if (IS_64(WordType)) {
    SERIALIZE(padded_data, (uint64_t) 0) // To simulate size of 128 bits...
  }
  SERIALIZE(padded_data, data_length)
  return padded_data;
}

#pragma clang diagnostic pop

}

#endif //HCL_SRC_SERVICES_CRYPTO_HASHFUNCTIONS_SHA2_H_
