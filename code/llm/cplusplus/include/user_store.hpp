#pragma once
#include <string>
#include <unordered_map>
#include <mutex>

class UserStore {
public:
    bool add_user(const std::string& email, const std::string& password);
    bool authenticate_user(const std::string& email, const std::string& password);
    bool delete_user(const std::string& email);

private:
    std::unordered_map<std::string, std::string> users_; // email -> hashed_password
    std::mutex mutex_; // Simple mutex for thread safety
};
