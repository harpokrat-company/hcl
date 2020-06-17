//
// Created by neodar on 16/06/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_BIGNUMBER_H_
#define HCL_SRC_SERVICES_CRYPTO_BIGNUMBER_H_

#include <vector>
#include <string>
#include <limits>
#include <stdexcept>

#define BASE_TYPE             uint8_t
#define BASE_SIZE             (sizeof(BASE_TYPE) * 8)
#define BASE_MAX              std::numeric_limits<BASE_TYPE>::max()
#define HALF_BASE_SIZE        (BASE_SIZE >> 1)
#define SQRT_BASE_MAX         (BASE_MAX >> (HALF_BASE_SIZE))

namespace HCL::Crypto {
class BigNumber {
 public:
  BigNumber(const std::string &number, const std::string &base);
  template<typename T>
  BigNumber(T number) :
      negative_(number < 0) {
    if (BASE_SIZE >= sizeof(number) * 8) {
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
  template<typename T>
  explicit operator T() const {
    T result = 0;

    if ((this->negative_ && *this < std::numeric_limits<T>::min())
        || (!this->negative_ && *this > std::numeric_limits<T>::max())) {
      throw std::overflow_error("BigNumber doesn't fit in type");
    }
    for (auto i : this->number_) {
      result *= 1 << BASE_SIZE;
      if (this->negative_) {
        result -= i;
      } else {
        result += i;
      }
    }

    return result;
  }
//  std::string ToBase(const std::string &base) const;
  BigNumber &operator=(const BigNumber &) = default;
  bool operator==(const BigNumber &) const;
  bool operator!=(const BigNumber &) const;
  bool operator>(const BigNumber &) const;
  bool operator<(const BigNumber &) const;
  bool operator>=(const BigNumber &) const;
  bool operator<=(const BigNumber &) const;
  BigNumber operator+(const BigNumber &) const;
  BigNumber operator-(const BigNumber &) const;
  BigNumber operator*(const BigNumber &) const;
//  BigNumber operator/(const BigNumber &) const;
//  BigNumber operator%(const BigNumber &) const;
  // TODO Potentially add bitwise operators
  BigNumber &operator+=(const BigNumber &);
  BigNumber &operator-=(const BigNumber &);
  BigNumber &operator*=(const BigNumber &);
  std::string TmpDumpHex() const {
    // TODO Remove and only working for BASE 256
    std::string output;
    static const std::string hex_base = "0123456789ABCDEF";

    for (const auto &digit : this->number_) {
      output = (char)hex_base[digit & SQRT_BASE_MAX] + output;
      output = (char)hex_base[digit >> HALF_BASE_SIZE] + output;
    }
    return output;
  }
 private:
  static void SetSubNumberDigit(std::vector<BASE_TYPE> &number, BASE_TYPE digit, size_t index);
  static void AddToSubNumberDigit(std::vector<BASE_TYPE> &number, BASE_TYPE value, size_t index);
  static BASE_TYPE GetSubNumberDigit(const std::vector<BASE_TYPE> &number, size_t index);
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
