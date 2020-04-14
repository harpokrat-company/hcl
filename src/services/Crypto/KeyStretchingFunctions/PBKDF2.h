//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_KEYSTRETCHING_PBKDF2_H_
#define HCL_SRC_SERVICES_CRYPTO_KEYSTRETCHING_PBKDF2_H_

#include <algorithm>
#include "../AutoRegisterer.h"
#include "AKeyStretchingFunction.h"
#include "../MessageAuthenticationCodes/AMessageAuthenticationCode.h"
#include "../RandomGenerators/ARandomGenerator.h"

namespace HCL::Crypto {

// TODO Find a way to set salt_len & iterations
// TODO Optimize everything
#define PBKDF2_DEFAULT_SALT_LENGTH  64
#define PBKDF2_DEFAULT_ITERATIONS   10000

class PBKDF2 : public AutoRegisterer<AKeyStretchingFunction, PBKDF2> {
 public:
  PBKDF2();
  PBKDF2(const std::string &header, size_t &header_length);
  const std::vector<std::string> &GetDependenciesTypes() override {
    static const std::vector<std::string> dependencies(
        {
            AMessageAuthenticationCode::GetName(),
            ARandomGenerator::GetName(),
        });
    return dependencies;
  }
  void SetDependency(std::unique_ptr<ACryptoElement> dependency, size_t index) override {
    if (index >= 2) {
      throw std::runtime_error("PBKDF2 error: Cannot set dependency: Incorrect dependency index");
    }
    switch (index) {
      case 0:SetMessageAuthenticationCode(std::move(dependency));
        break;
      case 1:
      default:SetRandomGenerator(std::move(dependency));
    }
  }
  bool IsDependencySet(size_t index) override {
    if (index >= 2) {
      throw std::runtime_error("PBKDF2 error: Cannot check dependency: Incorrect dependency index");
    }
    switch (index) {
      case 0:return IsMessageAuthenticationCodeSet();
      case 1:
      default:return IsRandomGeneratorSet();
    }
  }
  std::string StretchKey(const std::string &key, size_t derived_key_length) override;
  std::string GetHeader() override;
  void SetMessageAuthenticationCode(std::unique_ptr<ACryptoElement> message_authentication_code);
  bool IsMessageAuthenticationCodeSet() const;
  const ACryptoElement &GetMessageAuthenticationCode() const;
  void SetRandomGenerator(std::unique_ptr<ACryptoElement> random_generator);
  bool IsRandomGeneratorSet() const;
  const ACryptoElement &GetRandomGenerator() const;
  const std::string &GetElementName() override { return GetName(); };
  const std::string &GetElementTypeName() override { return GetTypeName(); };
  static const uint16_t id = 1;
  static const std::string &GetName() {
    static std::string name = "pbkdf2";
    return name;
  };
 private:
  std::string GetPBKDF2Bloc(const std::string &key, uint32_t bloc_index);
  void ParseSalt(const std::string &header, size_t &header_length);
  void ParseIterations(const std::string &header, size_t &header_length);
  std::string SerializeSalt();
  std::string SerializeIterations();
  std::unique_ptr<AMessageAuthenticationCode> message_authentication_code_;
  std::unique_ptr<ARandomGenerator> random_generator_;
  std::string salt_;
  bool is_salt_set_ = false;
  std::uint32_t iterations_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_KEYSTRETCHING_PBKDF2_H_
