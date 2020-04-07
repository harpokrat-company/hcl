//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_PADDING_APADDING_H_
#define HCL_SRC_SERVICES_CRYPTO_PADDING_APADDING_H_

#include <string>

namespace HCL::Crypto {

class APadding {
 public:
  virtual std::string PadDataToSize(const std::string &data, size_t size) = 0;
  virtual std::string RemovePadding(const std::string &data) = 0;
  virtual std::string GetHeader() = 0;
  static const std::string &GetName() {
    static std::string name = "padding";
    return name;
  };
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_PADDING_APADDING_H_
