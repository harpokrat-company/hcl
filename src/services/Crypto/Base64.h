//
// Created by neodar on 12/01/2020.
//

#ifndef HCL_BASE64_H
#define HCL_BASE64_H

#include <string>

namespace HCL::Crypto {

    class Base64 {
    public:
        static std::string Encode(const std::string &);
        static std::string Decode(const std::string &);
        static bool IsBase64(unsigned char);

    private:
        static const std::string base64_chars;
    };
}


#endif //HCL_BASE64_H
