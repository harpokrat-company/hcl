//
// Created by neodar on 13/01/2020.
//

#ifndef HCL_USER_H
#define HCL_USER_H

#include <string>
#include <utility>

namespace HCL {
class User {
 public:
  User(std::string, std::string, std::string, std::string);
  [[nodiscard]] const std::string &GetEmail() const;
  [[nodiscard]] const std::string &GetPassword() const;
  [[nodiscard]] const std::string &GetFirstName() const;
  [[nodiscard]] const std::string &GetLastName() const;
  void SetEmail(const std::string &);
  void SetPassword(const std::string &);
  void SetFirstName(const std::string &);
  void SetLastName(const std::string &);

 private:
  std::string email_;
  std::string password_;
  std::string first_name_;
  std::string last_name_;
};
}

#endif //HCL_USER_H
