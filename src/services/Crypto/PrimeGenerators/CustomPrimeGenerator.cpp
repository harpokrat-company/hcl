//
// Created by antoine on 27/06/2020.
//

#include "CustomPrimeGenerator.h"

HCL::Crypto::CustomPrimeGenerator::CustomPrimeGenerator() {
}

HCL::Crypto::CustomPrimeGenerator::CustomPrimeGenerator(const std::string &header, size_t &header_length) : CustomPrimeGenerator() {}

std::string HCL::Crypto::CustomPrimeGenerator::GetHeader() {
  if (!random_generator_) {
	throw std::runtime_error(GetDependencyUnsetError("get header", "Random generator"));
  }
  if (!primality_test_) {
	throw std::runtime_error(GetDependencyUnsetError("get header", "Primality test"));
  }
  return GetIdBytes() + random_generator_->GetHeader() + primality_test_->GetHeader();
}

void HCL::Crypto::CustomPrimeGenerator::SetRandomGenerator(std::unique_ptr<ACryptoElement> hash_function) {
  random_generator_ = ACryptoElement::UniqueTo<ARandomGenerator>(std::move(hash_function));
}

bool HCL::Crypto::CustomPrimeGenerator::IsRandomGeneratorSet() const {
  return !!random_generator_;
}

HCL::Crypto::ACryptoElement &HCL::Crypto::CustomPrimeGenerator::GetRandomGenerator() const {
  if (!IsRandomGeneratorSet()) {
	throw std::runtime_error(GetDependencyUnsetError("get Random generator", "Random generator"));
  }
  return *random_generator_;
}

void HCL::Crypto::CustomPrimeGenerator::SetPrimalityTest(std::unique_ptr<ACryptoElement> hash_function) {
  primality_test_ = ACryptoElement::UniqueTo<APrimalityTest>(std::move(hash_function));
}

bool HCL::Crypto::CustomPrimeGenerator::IsPrimalityTestSet() const {
  return !!primality_test_;
}

HCL::Crypto::ACryptoElement &HCL::Crypto::CustomPrimeGenerator::GetPrimalityTest() const {
  if (!IsPrimalityTestSet()) {
	throw std::runtime_error(GetDependencyUnsetError("get Primality test", "Primality test"));
  }
  return *primality_test_;
}

HCL::Crypto::BigNumber HCL::Crypto::CustomPrimeGenerator::GenerateRandomPrimeBigNumber(size_t bits) {
  //TODO: Implement generate random prime big number
  return HCL::Crypto::BigNumber("5", "0123456789");
}


