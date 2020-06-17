//
// Created by neodar on 16/06/2020.
//

#include "BigNumber.h"

HCL::Crypto::BigNumber::BigNumber(const std::string &number, const std::string &base) :
    negative_(false) {
  for (const auto &digit : number) {
    *this += base.find(digit);
    *this *= base.size();
  }
}

std::string HCL::Crypto::BigNumber::ToBase(const std::string &base) const {
  BigNumber tmp_copy(*this);
  std::string output_number;

  while (tmp_copy > 0) {
    output_number += base[tmp_copy % base.size()];
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
  for (auto i = this->number_.size() - 1; i >= 0; --i) {
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

HCL::Crypto::BigNumber HCL::Crypto::BigNumber::operator-(const HCL::Crypto::BigNumber &right_hand_side) const {
  BigNumber new_number(*this);

  new_number -= right_hand_side;
  return new_number;
}

HCL::Crypto::BigNumber &HCL::Crypto::BigNumber::operator-=(const HCL::Crypto::BigNumber &right_hand_side) {
  if (*this > right_hand_side) {
    this->SubtractBigNumber(right_hand_side);
  } else {
    BigNumber tmp(*this);

    *this = right_hand_side;
    this->SubtractBigNumber(tmp);
    this->negative_ = !this->negative_;
  }

  return *this;
}

void HCL::Crypto::BigNumber::SetNumberDigit(BASE_TYPE digit, size_t index) {
  while (this->number_.size() <= index) {
    this->number_.push_back(0);
  }
  this->number_[index] = digit;
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
  for (auto i = this->number_.size() - 1; i >= 0; --i) {
    if (this->GetNumberDigit(i) == 0) {
      this->number_.pop_back();
    }
  }
}
