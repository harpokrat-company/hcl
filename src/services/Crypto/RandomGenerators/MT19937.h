//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_RANDOMGENERATORS_MT19937_H_
#define HCL_SRC_SERVICES_CRYPTO_RANDOMGENERATORS_MT19937_H_

#include <random>
#include "../AutoRegisterer.h"
#include "ARandomGenerator.h"

namespace HCL::Crypto {

class MT19937 : public AutoRegisterer<ARandomGenerator, MT19937> {
 public:
  MT19937();
  MT19937(const std::string &header, size_t &header_length);
  const std::vector<std::string> &GetDependenciesTypes() override {
    static const std::vector<std::string> dependencies({});
    return dependencies;
  }
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
    throw std::runtime_error(GetDependencyIndexError("set"));
  }
  bool IsDependencySet(size_t index) override {
    throw std::runtime_error(GetDependencyIndexError("check"));
  }
  ACryptoElement &GetDependency(size_t index) override {
    throw std::runtime_error(GetDependencyIndexError("get"));
  }
  uint8_t GenerateRandomByte() override;
  std::string GenerateRandomByteSequence(size_t sequence_length) override;
  std::string GetHeader() override;
  const std::string &GetElementName() const override { return GetName(); };
  const std::string &GetElementTypeName() const override { return GetTypeName(); };
  static const uint16_t id = 1;
  static const std::string &GetName() {
    static std::string name = "mt19937";
    return name;
  };
 private:
  std::random_device random_device_;
  std::mt19937 generator_;
  std::uniform_int_distribution<uint8_t> distribution_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_RANDOMGENERATORS_MT19937_H_
