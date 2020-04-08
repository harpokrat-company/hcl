//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_KEYSTRETCHING_PBKDF2_H_
#define HCL_SRC_SERVICES_CRYPTO_KEYSTRETCHING_PBKDF2_H_

#include <algorithm>
#include "../AutoRegisterer.h"
#include "AKeyStretchingFunction.h"
#include "../MessageAuthenticationCodes/AMessageAuthenticationCode.h"

namespace HCL::Crypto {

class PBKDF2 : AutoRegisterer<AKeyStretchingFunction, PBKDF2> {
 public:
  PBKDF2() = default; // TODO Add RandomGenerator for salt && Find a way to set salt_len & iterations
  PBKDF2(const std::string &header, size_t &header_length);
  const std::vector<std::string> &GetRequiredDependencies() override {
    static const std::vector<std::string> dependencies(
        {
            AMessageAuthenticationCode::GetName(),
        });
    return dependencies;
  }
  void SetDependency(std::unique_ptr<AutoRegistrable> dependency, size_t index) override {
    if (index >= 1) {
      throw std::runtime_error("PBKDF2 error: Cannot set dependency: Incorrect dependency index");
    }
    switch (index) {
      case 0:
      default:
        SetMessageAuthenticationCode(std::move(dependency));
    }
  }
  std::string StretchKey(const std::string &key, size_t derived_key_length) override;
  std::string GetHeader() override;
  void SetMessageAuthenticationCode(std::unique_ptr<AutoRegistrable> message_authentication_code);
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
  std::string salt_;
  std::uint32_t iterations_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_KEYSTRETCHING_PBKDF2_H_
