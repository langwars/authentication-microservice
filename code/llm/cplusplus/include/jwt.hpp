#pragma once
#include <string>
#include <string_view>

class JWT {
public:
    static std::string create(const std::string& email);
    static bool verify(const std::string& token, std::string& email);
private:
    static constexpr const char* SECRET_KEY = "your-256-bit-secret"; // In production, load from env
    static std::string base64_encode(const std::string& input);
    static std::string base64_decode(const std::string& input);
    static std::string create_signature(const std::string& header_payload);
};
