#include "user_store.hpp"
#include "crypto.hpp"

bool UserStore::add_user(const std::string& email, const std::string& password) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (users_.find(email) != users_.end()) {
        return false;
    }
    
    users_[email] = crypto::hash_password(password);
    return true;
}

bool UserStore::authenticate_user(const std::string& email, const std::string& password) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = users_.find(email);
    if (it == users_.end()) {
        return false;
    }
    
    return crypto::verify_password(password, it->second);
}

bool UserStore::delete_user(const std::string& email) {
    std::lock_guard<std::mutex> lock(mutex_);
    return users_.erase(email) > 0;
}
