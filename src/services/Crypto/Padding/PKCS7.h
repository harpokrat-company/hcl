//
// Created by neodar on 07/04/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_PADDING_PKCS7_H_
#define HCL_SRC_SERVICES_CRYPTO_PADDING_PKCS7_H_

#include "../AutoRegisterer.h"
#include "APadding.h"
namespace HCL::Crypto {

class PKCS7 : public AutoRegisterer<APadding, PKCS7> {
 public:
  PKCS7(const std::string &header, size_t &header_length) {
    is_registered_;
  };
  std::string PadDataToSize(const std::string &data, size_t size) override;
  std::string RemovePadding(const std::string &data) override;
  std::string GetHeader() override;
  static const uint16_t Id = 1;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_PADDING_PKCS7_H_
