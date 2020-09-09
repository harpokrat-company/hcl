//
// Created by neodar on 08/04/2020.
//

#include <stdexcept>
#include "ACryptoElement.h"
#include "SuperFactory.h"

void HCL::Crypto::ACryptoElement::InstantiateDependency(const std::string &name, size_t index) {
  const std::vector<std::string> &dependenciesTypes = GetDependenciesTypes();

  if (index >= dependenciesTypes.size()) {
    throw std::runtime_error(GetDependencyIndexError("instantiate"));
  }

  SetDependency(std::move(SuperFactory::GetFactoryOfType(dependenciesTypes[index]).BuildFromName(name)), index);
}

std::string HCL::Crypto::ACryptoElement::GetError(const std::string &action, const std::string &details) const {
  const std::string origin = "CryptoElement " + GetElementName() + "(" + GetElementTypeName() + ")";
  const std::string context = "Can't " + action;

  return std::string(origin + ": " + context + ": " + details);
}

std::string HCL::Crypto::ACryptoElement::GetDependencyIndexError(const std::string &action) const {
  return GetError(action + " dependency", "Incorrect dependency index");
}

std::string HCL::Crypto::ACryptoElement::GetDependencyUnsetError(const std::string &action,
                                                                 const std::string &dependency) const {
  return GetError(action, dependency + " is not set");
}
