//
// Created by neodar on 22/11/2020.
//

#include "IncorrectSecret.h"

bool HCL::IncorrectSecret::DeserializeContent(const std::string &content) {
  return true;
}

std::string HCL::IncorrectSecret::SerializeContent() const {
  return std::string();
}

bool HCL::IncorrectSecret::CorrectDecryption() const {
  return false;
}
