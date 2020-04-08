//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_AINITIALIZATIONVECTORBLOCKCIPHERMODE_H_
#define HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_AINITIALIZATIONVECTORBLOCKCIPHERMODE_H_

#include <string>
#include <memory>
#include "../RandomGenerators/ARandomGenerator.h"

namespace HCL::Crypto {

class AInitializationVectorBlockCipherMode : public ACryptoElement {
 public:
  AInitializationVectorBlockCipherMode() = default;
  AInitializationVectorBlockCipherMode(const std::string &header, size_t &header_length);
  virtual std::string GetHeader();
  void SetRandomGenerator(std::unique_ptr<ACryptoElement> random_generator);
 protected:
  std::string GetInitializationVector(size_t initialization_vector_length);
 private:
  std::unique_ptr<ARandomGenerator> random_generator_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BLOCKCIPHERMODES_AINITIALIZATIONVECTORBLOCKCIPHERMODE_H_
