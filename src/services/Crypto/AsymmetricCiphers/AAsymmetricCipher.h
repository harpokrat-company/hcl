//
// Created by antoine on 20/07/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_AASYMMETRICCIPHER_H_
#define HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_AASYMMETRICCIPHER_H_

#include "../ACryptoElement.h"

namespace HCL::Crypto {

class AAsymmetricCipher : public ACryptoElement {
 public:
  virtual ~AAsymmetricCipher() = default;
  virtual std::string Encrypt(const std::string &key, const std::string &content) = 0;
  virtual std::string Decrypt(const std::string &key, const std::string &content) = 0;
  //TODO: Think about the KeyPair Generation
  //virtual UNKNOWN_TYPE KeyPairGenerator(size_t bits) = 0;
  virtual std::string GetHeader() = 0;
  static const std::string &GetName() {
	static std::string name = "asymmetric-cipher";
	return name;
  };
 private:
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_ASYMMETRICCIPHERS_AASYMMETRICCIPHER_H_
