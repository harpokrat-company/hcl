//
// Created by neodar on 16/06/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BIGNUMBER_H_
#define HCL_SRC_SERVICES_CRYPTO_BIGNUMBER_H_

#include <vector>
#include <string>
#include <limits>

#define BASE_TYPE unsigned char
#define BASE_SIZE sizeof(BASE_TYPE)
#define BASE_MAX  std::numeric_limits<BASE_TYPE>::max()

namespace HCL::Crypto {
class BigNumber {
 public:
  BigNumber(const std::string &number, const std::string &base);
  explicit BigNumber(const std::string &number) :
      BigNumber(number, "0123456789") {
  }
  BigNumber() :
      number_({0}),
      negative_(false) {
  }
  BigNumber(const BigNumber &original) = default;
  std::string ToBase(const std::string &base) const;
  BigNumber operator+(const BigNumber &) const;
  BigNumber &operator+=(const BigNumber &);
  BigNumber operator-(const BigNumber &) const;
  BigNumber &operator-=(const BigNumber &);
 private:
  void SetNumberDigit(BASE_TYPE digit, size_t index);
  BASE_TYPE GetNumberDigit(size_t index);
  void AddBigNumber(const BigNumber &);
  void SubtractBigNumber(const BigNumber &);
  std::vector<BASE_TYPE> number_;
  bool negative_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BIGNUMBER_H_
