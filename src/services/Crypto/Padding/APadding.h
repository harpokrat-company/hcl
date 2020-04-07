//
// Created by neodar on 06/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_PADDING_APADDING_H_
#define HCL_SRC_SERVICES_CRYPTO_PADDING_APADDING_H_

namespace HCL::Crypto {

class APadding {
  virtual std::string PadDataToSize(const std::string &data, size_t size) = 0;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_PADDING_APADDING_H_