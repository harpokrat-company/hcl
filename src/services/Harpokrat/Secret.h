//
// Created by neodar on 12/01/2020.
//

#ifndef HCL_SECRET_H
#define HCL_SECRET_H

#include <string>

namespace HCL {
union SerializedSecretHeader {
  uint16_t fields_sizes[4];
  char bytes[8];
};

class Secret {
 public:
  explicit Secret(const std::string &);
  explicit Secret() = default;
  [[nodiscard]] std::string Serialize() const;
  [[nodiscard]] const std::string &GetName() const;
  [[nodiscard]] const std::string &GetLogin() const;
  [[nodiscard]] const std::string &GetPassword() const;
  [[nodiscard]] const std::string &GetDomain() const;
  void SetName(const std::string &);
  void SetLogin(const std::string &);
  void SetPassword(const std::string &);
  void SetDomain(const std::string &);

 private:
  std::string name_;
  std::string login_;
  std::string password_;
  std::string domain_;

  void Deserialize(const std::string &);
};
}

#endif //HCL_SECRET_H
