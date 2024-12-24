#include "crypto.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sstream>
#include <iomanip>

namespace {
    const char* SECRET_KEY = "YOUR_SUPER_SECRET";
    
    std::string bytes_to_hex(const unsigned char* data, size_t len) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; ++i) {
            ss << std::setw(2) << static_cast<int>(data[i]);
        }
        return ss.str();
    }
}

namespace crypto {
    std::string hash_password(const std::string& password) {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;
        
        HMAC(EVP_sha256(), SECRET_KEY, strlen(SECRET_KEY),
             reinterpret_cast<const unsigned char*>(password.c_str()),
             password.length(), hash, &hash_len);
        
        return bytes_to_hex(hash, hash_len);
    }
    
    bool verify_password(const std::string& password, const std::string& stored_hash) {
        std::string computed_hash = hash_password(password);
        return computed_hash == stored_hash;
    }
}
