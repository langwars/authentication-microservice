#include "jwt.hpp"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <vector>

using json = nlohmann::json;

std::string JWT::base64_encode(const std::string& input) {
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    size_t in_len = input.length();
    const unsigned char* bytes_to_encode = reinterpret_cast<const unsigned char*>(input.c_str());
    
    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for(i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }
    
    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        
        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];
    }
    
    return ret;
}

std::string JWT::base64_decode(const std::string& encoded_string) {
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    
    std::string ret;
    std::vector<int> char_map(256, -1);
    for (size_t i = 0; i < base64_chars.length(); i++)
        char_map[base64_chars[i]] = i;
    
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    
    for (char c : encoded_string) {
        if (char_map[c] == -1) break;
        char_array_4[i++] = c;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = char_map[char_array_4[i]];
            
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            
            for (i = 0; i < 3; i++)
                ret += char_array_3[i];
            i = 0;
        }
    }
    
    if (i) {
        for (j = 0; j < i; j++)
            char_array_4[j] = char_map[char_array_4[j]];
        
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        
        for (j = 0; j < i - 1; j++)
            ret += char_array_3[j];
    }
    
    return ret;
}

std::string JWT::create_signature(const std::string& header_payload) {
    unsigned char* digest = HMAC(EVP_sha256(), 
                                SECRET_KEY, strlen(SECRET_KEY),
                                reinterpret_cast<const unsigned char*>(header_payload.c_str()),
                                header_payload.length(), nullptr, nullptr);
    return std::string(reinterpret_cast<char*>(digest), 32);
}

std::string JWT::create(const std::string& email) {
    json header = {
        {"alg", "HS256"},
        {"typ", "JWT"}
    };
    
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(24);
    
    json payload = {
        {"email", email},
        {"iat", std::chrono::system_clock::to_time_t(now)},
        {"exp", std::chrono::system_clock::to_time_t(exp)}
    };
    
    std::string header_encoded = base64_encode(header.dump());
    std::string payload_encoded = base64_encode(payload.dump());
    
    std::string header_payload = header_encoded + "." + payload_encoded;
    std::string signature = create_signature(header_payload);
    std::string signature_encoded = base64_encode(signature);
    
    return header_payload + "." + signature_encoded;
}

bool JWT::verify(const std::string& token, std::string& email) {
    size_t first_dot = token.find('.');
    size_t last_dot = token.rfind('.');
    
    if (first_dot == std::string::npos || last_dot == std::string::npos || first_dot == last_dot) {
        return false;
    }
    
    std::string header_payload = token.substr(0, last_dot);
    std::string provided_sig = base64_decode(token.substr(last_dot + 1));
    std::string computed_sig = create_signature(header_payload);
    
    if (provided_sig != computed_sig) {
        return false;
    }
    
    std::string payload_encoded = token.substr(first_dot + 1, last_dot - first_dot - 1);
    std::string payload_str = base64_decode(payload_encoded);
    
    try {
        json payload = json::parse(payload_str);
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        
        if (payload["exp"].get<time_t>() < now) {
            return false;
        }
        
        email = payload["email"].get<std::string>();
        return true;
    } catch (...) {
        return false;
    }
}
