//
// Created by neodar on 13/01/2020.
//

#include "user.h"

extern "C" {
    HCL::User *CreateUser(
            const char *email,
            const char *password,
            const char *first_name,
            const char *last_name
    ) {
        return new HCL::User(email, password, first_name, last_name);
    }

    const char *GetEmailFromUser(HCL::User *user) {
        return user->GetEmail().c_str();
    }

    void UpdateUserEmail(HCL::User *user, const char *email) {
        user->SetEmail(email);
    }

    const char *GetPasswordFromUser(HCL::User *user) {
        return user->GetPassword().c_str();
    }

    void UpdateUserPassword(HCL::User *user, const char *password) {
        user->SetPassword(password);
    }

    const char *GetFirstNameFromUser(HCL::User *user) {
        return user->GetFirstName().c_str();
    }

    void UpdateUserFirstName(HCL::User *user, const char *first_name) {
        user->SetFirstName(first_name);
    }

    const char *GetLastNameFromUser(HCL::User *user) {
        return user->GetLastName().c_str();
    }

    void UpdateUserLastName(HCL::User *user, const char *last_name) {
        user->SetLastName(last_name);
    }

    void DeleteUser(HCL::User *user) {
        delete user;
    }
}
