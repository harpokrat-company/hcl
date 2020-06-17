//
// Created by neodar on 16/06/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BIGNUMBER_H_
#define HCL_SRC_SERVICES_CRYPTO_BIGNUMBER_H_

#include <vector>
#include <string>
#include <limits>

#define BASE_TYPE             uint8_t
#define BASE_SIZE             sizeof(BASE_TYPE)
#define BASE_MAX              std::numeric_limits<BASE_TYPE>::max()

namespace HCL::Crypto {
class BigNumber {
 public:
  BigNumber(const std::string &number, const std::string &base);
  BigNumber(const std::string &number) :
      BigNumber(number, "0123456789") {
  }
  template<typename T>
  BigNumber(T number) :
      negative_(number < 0) {
    if (BASE_SIZE >= sizeof(number)) {
      this->SetNumberDigit(number < 0 ? number * -1 : number, 0);
    } else {
      size_t i = 0;

      while (number != 0) {
        this->SetNumberDigit(number & BASE_MAX, i++);
        number /= 1 << BASE_SIZE;
      }
    }
  }
  BigNumber() :
      number_({0}),
      negative_(false) {
  }
  BigNumber(const BigNumber &original) = default;
  std::string ToBase(const std::string &base) const;
  BigNumber &operator=(const BigNumber &) = default;
  bool operator==(const BigNumber &) const;
  bool operator!=(const BigNumber &) const;
  bool operator>(const BigNumber &) const;
  bool operator<(const BigNumber &) const;
  bool operator>=(const BigNumber &) const;
  bool operator<=(const BigNumber &) const;
  BigNumber operator+(const BigNumber &) const;
  BigNumber &operator+=(const BigNumber &);
  BigNumber operator-(const BigNumber &) const;
  BigNumber &operator-=(const BigNumber &);
 private:
  void SetNumberDigit(BASE_TYPE digit, size_t index);
  BASE_TYPE GetNumberDigit(size_t index) const;
  void AddBigNumber(const BigNumber &);
  void SubtractBigNumber(const BigNumber &);
  void CleanNumber();
  std::vector<BASE_TYPE> number_;
  bool negative_;
};
}

#endif //HCL_SRC_SERVICES_CRYPTO_BIGNUMBER_H_
