#pragma once
#include <string>

namespace crypto {
    // Hash a password using HMAC-SHA256 with a secret key
    std::string hash_password(const std::string& password);
    
    // Verify a password against its hash
    bool verify_password(const std::string& password, const std::string& hash);
}
