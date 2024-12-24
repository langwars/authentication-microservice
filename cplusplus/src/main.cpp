#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio.hpp>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include "user_store.hpp"
#include "jwt.hpp"
#include <nlohmann/json.hpp>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;
using json = nlohmann::json;

// This function produces a JSON response
template<class Body, class Allocator>
http::response<http::string_body> 
make_json_response(
    const http::request<Body, http::basic_fields<Allocator>>& req,
    const std::string& json_str,
    http::status status)
{
    http::response<http::string_body> res{status, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "application/json");
    res.set(http::field::access_control_allow_origin, "*");
    res.keep_alive(req.keep_alive());
    res.body() = json_str;
    res.prepare_payload();
    return res;
}

class HttpSession : public std::enable_shared_from_this<HttpSession> {
    tcp::socket socket_;
    beast::flat_buffer buffer_;
    std::shared_ptr<UserStore> user_store_;
    http::request<http::string_body> request_;
    http::response<http::string_body> response_;

public:
    HttpSession(tcp::socket socket, std::shared_ptr<UserStore> store)
        : socket_(std::move(socket))
        , user_store_(store)
    {
    }

    void run() {
        do_read();
    }

private:
    void do_read() {
        request_ = {};
        buffer_.consume(buffer_.size());

        auto self = shared_from_this();
        http::async_read(
            socket_,
            buffer_,
            request_,
            [self](beast::error_code ec, std::size_t) {
                if (ec == http::error::end_of_stream) {
                    return self->do_close();
                }
                if (ec) {
                    return;
                }
                self->handle_request();
            });
    }

    void handle_request() {
        if (request_.target() == "/register" && request_.method() == http::verb::post) {
            try {
                auto data = json::parse(request_.body());
                std::string email = data["email"];
                std::string password = data["password"];

                if (user_store_->add_user(email, password)) {
                    std::string token = JWT::create(email);
                    response_ = make_json_response(request_, "{\"token\": \"" + token + "\"}", http::status::ok);
                } else {
                    response_ = make_json_response(request_, "{\"error\": \"User already exists\"}", http::status::bad_request);
                }
            } catch (...) {
                response_ = make_json_response(request_, "{\"error\": \"Invalid JSON or missing fields\"}", http::status::bad_request);
            }
        }
        else if (request_.target() == "/login" && request_.method() == http::verb::post) {
            try {
                auto data = json::parse(request_.body());
                std::string email = data["email"];
                std::string password = data["password"];

                if (user_store_->authenticate_user(email, password)) {
                    std::string token = JWT::create(email);
                    response_ = make_json_response(request_, "{\"token\": \"" + token + "\"}", http::status::ok);
                } else {
                    response_ = make_json_response(request_, "{\"error\": \"Invalid credentials\"}", http::status::unauthorized);
                }
            } catch (...) {
                response_ = make_json_response(request_, "{\"error\": \"Invalid JSON or missing fields\"}", http::status::bad_request);
            }
        }
        else if (request_.target() == "/delete" && request_.method() == http::verb::delete_) {
            auto auth_it = request_.find("Authorization");
            if (auth_it == request_.end()) {
                response_ = make_json_response(request_, "{\"error\": \"Missing Authorization header\"}", http::status::unauthorized);
            }
            else {
                std::string auth_header = auth_it->value();
                if (auth_header.substr(0, 7) != "Bearer ") {
                    response_ = make_json_response(request_, "{\"error\": \"Malformed Authorization header\"}", http::status::unauthorized);
                }
                else {
                    std::string token = auth_header.substr(7);
                    std::string email;

                    if (!JWT::verify(token, email)) {
                        response_ = make_json_response(request_, "{\"error\": \"Invalid or expired token\"}", http::status::unauthorized);
                    }
                    else if (user_store_->delete_user(email)) {
                        response_ = make_json_response(request_, "{\"success\": true}", http::status::ok);
                    }
                    else {
                        response_ = make_json_response(request_, "{\"success\": false, \"error\": \"User not found\"}", http::status::bad_request);
                    }
                }
            }
        }
        else {
            response_ = make_json_response(request_, "{\"error\": \"Not Found\"}", http::status::not_found);
        }

        do_write();
    }

    void do_write() {
        auto self = shared_from_this();
        http::async_write(
            socket_,
            response_,
            [self](beast::error_code ec, std::size_t) {
                if (ec) {
                    return;
                }
                if (self->response_.need_eof()) {
                    return self->do_close();
                }
                self->do_read();
            });
    }

    void do_close() {
        beast::error_code ec;
        socket_.shutdown(tcp::socket::shutdown_send, ec);
    }
};

class Listener : public std::enable_shared_from_this<Listener> {
    net::io_context& ioc_;
    tcp::acceptor acceptor_;
    std::shared_ptr<UserStore> user_store_;

public:
    Listener(net::io_context& ioc, tcp::endpoint endpoint, std::shared_ptr<UserStore> store)
        : ioc_(ioc)
        , acceptor_(ioc)
        , user_store_(store)
    {
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(net::socket_base::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen(net::socket_base::max_listen_connections);
    }

    void run() {
        do_accept();
    }

private:
    void do_accept() {
        auto self = shared_from_this();
        acceptor_.async_accept(
            [self](beast::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<HttpSession>(
                        std::move(socket),
                        self->user_store_)->run();
                }
                self->do_accept();
            });
    }
};

int main() {
    try {
        auto const address = net::ip::make_address("0.0.0.0");
        auto const port = static_cast<unsigned short>(3000);
        auto const threads = std::thread::hardware_concurrency();

        net::io_context ioc{static_cast<int>(threads)};
        auto user_store = std::make_shared<UserStore>();

        std::make_shared<Listener>(
            ioc,
            tcp::endpoint{address, port},
            user_store)->run();

        std::cout << "Server listening on port " << port << std::endl;

        std::vector<std::thread> v;
        v.reserve(threads - 1);
        for(auto i = threads - 1; i > 0; --i)
            v.emplace_back(
                [&ioc] {
                    ioc.run();
                });
        ioc.run();

        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
