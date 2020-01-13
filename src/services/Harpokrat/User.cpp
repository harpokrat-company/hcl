//
// Created by neodar on 13/01/2020.
//

#include "User.h"

#include <utility>

HCL::User::User(
        std::string email,
        std::string password,
        std::string first_name,
        std::string last_name) :
        email_(std::move(email)),
        password_(std::move(password)),
        first_name_(std::move(first_name)),
        last_name_(std::move(last_name)) {
}

const std::string &HCL::User::GetEmail() const {
    return this->email_;
}

const std::string &HCL::User::GetPassword() const {
    return this->password_;
}

const std::string &HCL::User::GetFirstName() const {
    return this->first_name_;
}

const std::string &HCL::User::GetLastName() const {
    return this->last_name_;
}

void HCL::User::SetEmail(const std::string &email) {
    this->email_ = email;
}

void HCL::User::SetPassword(const std::string &password) {
    this->password_ = password;
}

void HCL::User::SetFirstName(const std::string &first_name) {
    this->first_name_ = first_name;
}

void HCL::User::SetLastName(const std::string &last_name) {
    this->last_name_ = last_name;
}
