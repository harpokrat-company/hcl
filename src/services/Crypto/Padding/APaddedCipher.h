//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_PADDING_APADDEDCIPHER_H_
#define HCL_SRC_SERVICES_CRYPTO_PADDING_APADDEDCIPHER_H_

#include <string>
#include <memory>
#include "APadding.h"

namespace HCL::Crypto {

class APaddedCipher : public ACryptoElement {
 public:
  APaddedCipher() = default;
  APaddedCipher(const std::string &header, size_t &header_length);
  virtual ~APaddedCipher() = default;
  virtual std::string GetHeader();
  void SetPadding(std::unique_ptr<ACryptoElement> padding);
  bool IsPaddingSet() const;
  const ACryptoElement &GetPadding() const;
 protected:
  std::unique_ptr<APadding> padding_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_PADDING_APADDEDCIPHER_H_
