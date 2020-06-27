//
// Created by neodar on 16/06/2020.
//

#include "BigNumber.h"

HCL::Crypto::BigNumber::BigNumber(const std::string &number, const std::string &base) :
    negative_(false),
    number_() {
  for (const auto &digit : number) {
    *this *= base.size();
    *this += base.find(digit);
  }
}

std::string HCL::Crypto::BigNumber::ToBase(const std::string &base) const {
  BigNumber tmp_copy(*this);
  std::string output_number;

  while (tmp_copy > 0) {
    output_number = base[static_cast<size_t>(tmp_copy % base.size())] + output_number;
    tmp_copy /= base.size();
  }
  return output_number;
}

bool HCL::Crypto::BigNumber::operator==(const HCL::Crypto::BigNumber &right_hand_side) const {
  if (this->negative_ != right_hand_side.negative_
      || this->number_.size() != right_hand_side.number_.size()) {
    return false;
  }
  for (auto i = 0; i < this->number_.size(); ++i) {
    if (this->GetNumberDigit(i) != right_hand_side.GetNumberDigit(i)) {
      return false;
    }
  }
  return true;
}

bool HCL::Crypto::BigNumber::operator!=(const HCL::Crypto::BigNumber &right_hand_side) const {
  return !(*this == right_hand_side);
}

bool HCL::Crypto::BigNumber::operator>(const HCL::Crypto::BigNumber &right_hand_side) const {
  if (this->negative_ != right_hand_side.negative_) {
    return !this->negative_;
  }
  if (this->number_.size() != right_hand_side.number_.size()) {
    return this->number_.size() > right_hand_side.number_.size();
  }
  for (ssize_t i = this->number_.size() - 1; i >= 0; --i) {
    if (this->number_[i] != right_hand_side.number_[i]) {
      return this->number_[i] > right_hand_side.number_[i];
    }
  }
  return false;
}

bool HCL::Crypto::BigNumber::operator<(const HCL::Crypto::BigNumber &right_hand_side) const {
  return right_hand_side > *this;
}

bool HCL::Crypto::BigNumber::operator>=(const HCL::Crypto::BigNumber &right_hand_side) const {
  return (*this > right_hand_side) || (*this == right_hand_side);
}

bool HCL::Crypto::BigNumber::operator<=(const HCL::Crypto::BigNumber &right_hand_side) const {
  return (*this < right_hand_side) || (*this == right_hand_side);
}

HCL::Crypto::BigNumber HCL::Crypto::BigNumber::operator+(const HCL::Crypto::BigNumber &right_hand_side) const {
  BigNumber new_number(*this);

  new_number += right_hand_side;
  return new_number;
}

HCL::Crypto::BigNumber HCL::Crypto::BigNumber::operator-(const HCL::Crypto::BigNumber &right_hand_side) const {
  BigNumber new_number(*this);

  new_number -= right_hand_side;
  return new_number;
}

HCL::Crypto::BigNumber HCL::Crypto::BigNumber::operator*(const HCL::Crypto::BigNumber &right_hand_side) const {
  BigNumber new_number(*this);

  new_number *= right_hand_side;
  return new_number;
}

HCL::Crypto::BigNumber HCL::Crypto::BigNumber::operator/(const HCL::Crypto::BigNumber &right_hand_side) const {
  BigNumber new_number(*this);

  new_number /= right_hand_side;
  return new_number;
}

HCL::Crypto::BigNumber HCL::Crypto::BigNumber::operator%(const HCL::Crypto::BigNumber &right_hand_side) const {
  BigNumber new_number(*this);

  new_number %= right_hand_side;
  return new_number;
}

HCL::Crypto::BigNumber HCL::Crypto::BigNumber::operator&(const HCL::Crypto::BigNumber &right_hand_side) const {
  BigNumber new_number(*this);

  new_number &= right_hand_side;
  return new_number;
}

HCL::Crypto::BigNumber HCL::Crypto::BigNumber::operator|(const HCL::Crypto::BigNumber &right_hand_side) const {
  BigNumber new_number(*this);

  new_number |= right_hand_side;
  return new_number;
}

HCL::Crypto::BigNumber HCL::Crypto::BigNumber::operator^(const HCL::Crypto::BigNumber &right_hand_side) const {
  BigNumber new_number(*this);

  new_number ^= right_hand_side;
  return new_number;
}

HCL::Crypto::BigNumber HCL::Crypto::BigNumber::operator>>(size_t right_hand_side) const {
  BigNumber new_number(*this);

  new_number >>= right_hand_side;
  return new_number;
}

HCL::Crypto::BigNumber HCL::Crypto::BigNumber::operator<<(size_t right_hand_side) const {
  BigNumber new_number(*this);

  new_number <<= right_hand_side;
  return new_number;
}

HCL::Crypto::BigNumber HCL::Crypto::BigNumber::operator~() const {
  BigNumber new_number(*this);

  for (auto &digit : new_number.number_) {
    digit = ~digit;
  }
  new_number.CleanNumber();
  return new_number;
}

HCL::Crypto::BigNumber &HCL::Crypto::BigNumber::operator+=(const HCL::Crypto::BigNumber &right_hand_side) {
  if (this->negative_ == right_hand_side.negative_) {
    this->AddBigNumber(right_hand_side);
  } else if (this->negative_) {
    *this = right_hand_side - *this;
  } else {
    *this -= right_hand_side;
  }

  return *this;
}

HCL::Crypto::BigNumber &HCL::Crypto::BigNumber::operator-=(const HCL::Crypto::BigNumber &right_hand_side) {
  if (this->negative_ == right_hand_side.negative_) {
    if (*this > right_hand_side) {
      this->SubtractBigNumber(right_hand_side);
    } else {
      BigNumber tmp(*this);

      *this = right_hand_side;
      this->SubtractBigNumber(tmp);
      this->negative_ = !this->negative_;
    }
  } else {
    this->negative_ = !this->negative_;
    this->AddBigNumber(right_hand_side);
    this->negative_ = !this->negative_;
  }

  return *this;
}

HCL::Crypto::BigNumber &HCL::Crypto::BigNumber::operator*=(const HCL::Crypto::BigNumber &right_hand_side) {
  // TODO Optimize square (same subproduct results both way)
  this->negative_ = this->negative_ != right_hand_side.negative_;
  std::vector<BASE_TYPE> result(this->number_.size() + right_hand_side.number_.size());

  for (auto lhs_index = 0; lhs_index < this->number_.size() * 2; ++lhs_index) {
    for (auto rhs_index = 0; rhs_index < right_hand_side.number_.size() * 2; ++rhs_index) {
      auto result_index = lhs_index + rhs_index;
      BASE_TYPE sub_digit_result = GetSubNumberDigit(this->number_, lhs_index)
          * GetSubNumberDigit(right_hand_side.number_, rhs_index);

      size_t i = 0;
      while (sub_digit_result > 0) {
        sub_digit_result += GetSubNumberDigit(result, result_index + i);
        SetSubNumberDigit(result, sub_digit_result % (SQRT_BASE_MAX + 1), result_index + i);
        sub_digit_result /= (SQRT_BASE_MAX + 1);
        i += 1;
      }
    }
  }
  this->number_ = result;
  this->CleanNumber();
  return *this;
}

HCL::Crypto::BigNumber &HCL::Crypto::BigNumber::operator/=(const HCL::Crypto::BigNumber &right_hand_side) {
  if (right_hand_side == 0) {
    throw std::overflow_error("Division by zero");
  }
  BigNumber sub_divident;
  BigNumber quotient;
  BigNumber divider(right_hand_side);
  this->negative_ = this->negative_ != right_hand_side.negative_;
  divider.negative_ = false;

  for (ssize_t i = this->number_.size() - 1; i >= 0; --i) {
    quotient <<= BASE_SIZE;
    sub_divident <<= BASE_SIZE;
    sub_divident += this->GetNumberDigit(i);
    while (sub_divident >= divider) {
      sub_divident -= divider;
      quotient += one;
    }
  }
  *this = quotient;
  this->CleanNumber();
  return *this;
}

HCL::Crypto::BigNumber &HCL::Crypto::BigNumber::operator%=(const HCL::Crypto::BigNumber &right_hand_side) {
  if (right_hand_side == 0) {
    throw std::overflow_error("Division by zero");
  }
  BigNumber sub_divident;
  BigNumber quotient;
  BigNumber divider(right_hand_side);
  this->negative_ = this->negative_ != right_hand_side.negative_;
  divider.negative_ = false;

  for (ssize_t i = this->number_.size() - 1; i >= 0; --i) {
    quotient <<= BASE_SIZE;
    sub_divident <<= BASE_SIZE;
    sub_divident += this->GetNumberDigit(i);
    while (sub_divident >= divider) {
      sub_divident -= divider;
      quotient += one;
    }
  }
  *this = sub_divident;
  this->CleanNumber();
  return *this;
}

HCL::Crypto::BigNumber &HCL::Crypto::BigNumber::operator&=(const HCL::Crypto::BigNumber &right_hand_side) {
  const size_t max_digits = this->number_.size() > right_hand_side.number_.size() ?
                            this->number_.size() : right_hand_side.number_.size();
  for (auto i = 0; i < max_digits; ++i) {
    this->SetNumberDigit(this->GetNumberDigit(i) & right_hand_side.GetNumberDigit(i), i);
  }

  this->CleanNumber();
  return *this;
}

HCL::Crypto::BigNumber &HCL::Crypto::BigNumber::operator|=(const HCL::Crypto::BigNumber &right_hand_side) {
  const size_t max_digits = this->number_.size() > right_hand_side.number_.size() ?
                            this->number_.size() : right_hand_side.number_.size();
  for (auto i = 0; i < max_digits; ++i) {
    this->SetNumberDigit(this->GetNumberDigit(i) | right_hand_side.GetNumberDigit(i), i);
  }

  this->CleanNumber();
  return *this;
}

HCL::Crypto::BigNumber &HCL::Crypto::BigNumber::operator^=(const HCL::Crypto::BigNumber &right_hand_side) {
  const size_t max_digits = this->number_.size() > right_hand_side.number_.size() ?
                            this->number_.size() : right_hand_side.number_.size();
  for (auto i = 0; i < max_digits; ++i) {
    this->SetNumberDigit(this->GetNumberDigit(i) ^ right_hand_side.GetNumberDigit(i), i);
  }

  this->CleanNumber();
  return *this;
}

HCL::Crypto::BigNumber &HCL::Crypto::BigNumber::operator>>=(size_t offset_counter) {
  while (offset_counter >= BASE_SIZE && this->number_.size() > 1) {
    this->number_.erase(this->number_.begin());
    offset_counter -= BASE_SIZE;
  }
  if (offset_counter >= BASE_SIZE) {
    *this = 0;
  } else {
    BASE_TYPE carry = 0;
    for (ssize_t i = this->number_.size() - 1; i >= 0; --i) {
      BASE_TYPE tmp_carry = (this->number_[i] & ((1 << offset_counter) - 1))
          << (BASE_SIZE - offset_counter);
      this->number_[i] >>= offset_counter;
      this->number_[i] += carry;
      carry = tmp_carry;
    }
  }
  this->CleanNumber();
  return *this;
}

HCL::Crypto::BigNumber &HCL::Crypto::BigNumber::operator<<=(size_t offset_counter) {
  this->number_.resize(this->number_.size() + (offset_counter / BASE_SIZE) + 1);
  while (offset_counter >= BASE_SIZE) {
    this->number_.insert(this->number_.begin(), 0);
    offset_counter -= BASE_SIZE;
    if (offset_counter < 0) {
      offset_counter = 0;
    }
  }
  BASE_TYPE carry = 0;
  for (auto &digit : this->number_) {
    BASE_TYPE tmp_carry = digit >> (BASE_SIZE - offset_counter);
    digit <<= offset_counter;
    digit += carry;
    carry = tmp_carry;
  }
  if (carry) {
    this->SetNumberDigit(carry, this->number_.size());
  }
  this->CleanNumber();
  return *this;
}

HCL::Crypto::BigNumber HCL::Crypto::BigNumber::Exponentiation(
    const HCL::Crypto::BigNumber &exponent
) const {
  BigNumber last_modular_power_of_two = *this;
  BigNumber exponent_counter(exponent);
  BigNumber total_modular_exponentiation(1);

  while (exponent_counter > 0) {
    if (exponent_counter & one) {
      total_modular_exponentiation *= last_modular_power_of_two;
    }
    last_modular_power_of_two *= last_modular_power_of_two;
    exponent_counter >>= 1;
  }
  total_modular_exponentiation.CleanNumber();
  return total_modular_exponentiation;
}

HCL::Crypto::BigNumber HCL::Crypto::BigNumber::ModularExponentiation(
    const HCL::Crypto::BigNumber &exponent,
    const HCL::Crypto::BigNumber &modulo
) const {
  BigNumber last_modular_power_of_two = *this % modulo;
  BigNumber exponent_counter(exponent);
  BigNumber total_modular_exponentiation(1);

  while (exponent_counter > 0) {
    if (exponent_counter & one) {
      total_modular_exponentiation *= last_modular_power_of_two;
      total_modular_exponentiation %= modulo;
    }
    last_modular_power_of_two *= last_modular_power_of_two;
    last_modular_power_of_two %= modulo;
    exponent_counter >>= 1;
  }
  total_modular_exponentiation.CleanNumber();
  return total_modular_exponentiation;
}

void HCL::Crypto::BigNumber::SetNumberDigit(BASE_TYPE digit, size_t index) {
  while (this->number_.size() <= index) {
    this->number_.push_back(0);
  }
  this->number_[index] = digit;
}

void HCL::Crypto::BigNumber::SetSubNumberDigit(std::vector<BASE_TYPE> &number, BASE_TYPE digit, size_t index) {
  while (number.size() <= index / 2) {
    number.push_back(0);
  }
  if (index % 2 == 0) {
    number[index / 2] >>= HALF_BASE_SIZE;
    number[index / 2] <<= HALF_BASE_SIZE;
    number[index / 2] |= digit;
  } else {
    number[index / 2] &= SQRT_BASE_MAX;
    number[index / 2] |= digit << HALF_BASE_SIZE;
  }
}

BASE_TYPE HCL::Crypto::BigNumber::GetSubNumberDigit(const std::vector<BASE_TYPE> &number, size_t index) {
  if (number.size() <= index / 2) {
    return 0;
  }
  if (index % 2 == 0) {
    return number[index / 2] & SQRT_BASE_MAX;
  } else {
    return number[index / 2] >> HALF_BASE_SIZE;
  }
}

BASE_TYPE HCL::Crypto::BigNumber::GetNumberDigit(size_t index) const {
  if (this->number_.size() <= index) {
    return 0;
  }
  return this->number_[index];
}

void HCL::Crypto::BigNumber::AddBigNumber(const HCL::Crypto::BigNumber &right_hand_side) {
  size_t digit_index = 0;
  bool carry = false;
  BASE_TYPE current_digit;

  while (right_hand_side.number_.size() > digit_index) {
    current_digit = carry ? 1 : 0;
    carry = this->GetNumberDigit(digit_index) > BASE_MAX - right_hand_side.number_[digit_index];
    if (carry) {
      current_digit += BASE_MAX
          - ((BASE_MAX - this->GetNumberDigit(digit_index)) + (BASE_MAX - right_hand_side.number_[digit_index]))
          - 1;
    } else {
      current_digit = this->GetNumberDigit(digit_index) + right_hand_side.number_[digit_index];
    }
    this->SetNumberDigit(current_digit, digit_index);
    digit_index += 1;
  }
  while (carry) {
    carry = this->GetNumberDigit(digit_index) == BASE_MAX;
    if (!carry) {
      this->SetNumberDigit(this->GetNumberDigit(digit_index) + 1, digit_index);
    }
    digit_index += 1;
  }
  this->CleanNumber();
}

void HCL::Crypto::BigNumber::SubtractBigNumber(const HCL::Crypto::BigNumber &right_hand_side) {
  size_t digit_index = 0;
  bool carry = false;
  BASE_TYPE current_digit;
  BASE_TYPE current_rhs_digit;

  while (right_hand_side.number_.size() > digit_index) {
    current_rhs_digit = right_hand_side.number_[digit_index];
    if (carry) {
      if (current_rhs_digit != BASE_MAX) {
        current_rhs_digit += 1;
      } else if (this->GetNumberDigit(digit_index) > 0) {
        this->SetNumberDigit(this->GetNumberDigit(digit_index) - 1, digit_index);
      } else {
        this->SetNumberDigit(0, digit_index);
        digit_index += 1;
        continue;
      }
    }
    carry = this->GetNumberDigit(digit_index) < current_rhs_digit;
    if (carry) {
      current_digit = BASE_MAX - (current_rhs_digit - this->GetNumberDigit(digit_index)) + 1;
    } else {
      current_digit = this->GetNumberDigit(digit_index) - current_rhs_digit;
    }
    this->SetNumberDigit(current_digit, digit_index);
    digit_index += 1;
  }
  while (carry) {
    carry = this->GetNumberDigit(digit_index) == 0;
    if (!carry) {
      this->SetNumberDigit(this->GetNumberDigit(digit_index) - 1, digit_index);
    }
    digit_index += 1;
  }
  this->CleanNumber();
}

void HCL::Crypto::BigNumber::CleanNumber() {
  for (ssize_t i = this->number_.size() - 1; i >= 0; --i) {
    if (this->GetNumberDigit(i) == 0) {
      this->number_.pop_back();
    } else {
      break;
    }
  }
  if (this->number_.empty()) {
    this->negative_ = false;
  }
}
