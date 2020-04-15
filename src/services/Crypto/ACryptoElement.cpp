//
// Created by neodar on 08/04/2020.
//

#include "ACryptoElement.h"
#include "SuperFactory.h"

void HCL::Crypto::ACryptoElement::InstantiateDependency(const std::string &name, size_t index) {
  const std::vector<std::string> &dependenciesTypes = GetDependenciesTypes();

  if (index >= dependenciesTypes.size()) {
    throw std::runtime_error("ACryptoElement: Cannot instantiate dependency: Incorrect dependency index");
  }

  SetDependency(std::move(SuperFactory::GetFactoryOfType(dependenciesTypes[index]).BuildFromName(name)), index);
}
