#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdatomic.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <ctype.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define SERVER_PORT 3000
#define MAX_BUFFER 4096
#define MAX_USERS (1 << 16)
#define HASH_BITS 16
#define HASH_SIZE (1 << HASH_BITS)
#define HASH_MASK (HASH_SIZE - 1)

static const char* SECRET_KEY = "your_secret_key";
static const char* HTTP_200 = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: ";
static const char* HTTP_400 = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 37\r\n\r\n{\"error\":\"Missing email or password\"}";
static const char* HTTP_401 = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 38\r\n\r\n{\"error\":\"Invalid email or password.\"}";

typedef struct {
    uint32_t hash;
    char email[32];
    uint8_t passhash[32];
    uint8_t in_use;
    uint8_t padding[7];
} __attribute__((aligned(64))) User;

static User* users;
static atomic_uint user_count = 0;

static inline uint32_t fnv1a_hash(const char* str) {
    uint32_t h = 2166136261u;
    while (*str) {
        h ^= (uint8_t)*str++;
        h *= 16777619u;
    }
    return h;
}

void init_users() {
    users = mmap(NULL, MAX_USERS * sizeof(User),
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (users == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
}

static inline User* find_user(const char* email) {
    uint32_t h = fnv1a_hash(email);
    uint32_t idx = h & HASH_MASK;
    for (uint32_t i = 0; i < HASH_SIZE; i++) {
        User* u = &users[idx];
        if (!u->in_use) return NULL;
        if (u->hash == h && strcmp(u->email, email) == 0) return u;
        idx = (idx + 1) & HASH_MASK;
    }
    return NULL;
}

static inline int create_user(const char* email, const uint8_t* passhash) {
    uint32_t h = fnv1a_hash(email);
    uint32_t idx = h & HASH_MASK;
    for (uint32_t i = 0; i < HASH_SIZE; i++) {
        User* u = &users[idx];
        if (!__atomic_test_and_set(&u->in_use, __ATOMIC_SEQ_CST)) {
            u->hash = h;
            strncpy(u->email, email, sizeof(u->email) - 1);
            memcpy(u->passhash, passhash, 32);
            atomic_fetch_add(&user_count, 1);
            return 1;
        } else {
            if (u->hash == h && strcmp(u->email, email) == 0) {
                // Log debug message
                printf("User already exists: %s\n", email);
                return 0;
            }
        }
        idx = (idx + 1) & HASH_MASK;
    }
    return 0;
}

static inline int remove_user(const char* email) {
    User* u = find_user(email);
    if (!u) return 0;
    __atomic_clear(&u->in_use, __ATOMIC_SEQ_CST);
    atomic_fetch_sub(&user_count, 1);
    memset(u->email, 0, sizeof(u->email));
    memset(u->passhash, 0, 32);
    u->hash = 0;
    return 1;
}

static inline size_t extract_json_string(const char* json, const char* field, char* out, size_t out_size) {
    const char* p = strstr(json, field);
    if (!p) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    p = strchr(p, '"');
    if (!p) return 0;
    p++;
    const char* end = strchr(p, '"');
    if (!end) return 0;
    size_t len = end - p;
    if (len >= out_size) return 0;
    memcpy(out, p, len);
    out[len] = '\0';
    return len;
}

static char* base64_url_encode(const unsigned char* input, int len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, len);
    BIO_flush(b64);
    BUF_MEM* buffer = NULL;
    BIO_get_mem_ptr(b64, &buffer);
    char* output = malloc(buffer->length + 1);
    if (!output) {
        BIO_free_all(b64);
        return NULL;
    }
    memcpy(output, buffer->data, buffer->length);
    output[buffer->length] = '\0';
    for (char* p = output; *p; ++p) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
        else if (*p == '=') *p = '\0';
    }
    BIO_free_all(b64);
    return output;
}

static unsigned char* base64_url_decode(const char* input, int* out_len) {
    char* temp = strdup(input);
    if (!temp) return NULL;
    for (char* p = temp; *p; ++p) {
        if (*p == '-') *p = '+';
        else if (*p == '_') *p = '/';
    }
    size_t len = strlen(temp);
    int pad = 4 - (len % 4);
    if (pad < 4) {
        char* newtemp = malloc(len + pad + 1);
        if (!newtemp) {
            free(temp);
            return NULL;
        }
        strcpy(newtemp, temp);
        for (int i = 0; i < pad; i++) newtemp[len + i] = '=';
        newtemp[len + pad] = '\0';
        free(temp);
        temp = newtemp;
        len += pad;
    }
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* bio = BIO_new_mem_buf(temp, len);
    bio = BIO_push(b64, bio);
    unsigned char* buffer = malloc(len);
    if (!buffer) {
        BIO_free_all(bio);
        free(temp);
        return NULL;
    }
    int decoded_len = BIO_read(bio, buffer, len);
    if (decoded_len < 0) {
        free(buffer);
        buffer = NULL;
        decoded_len = 0;
    }
    BIO_free_all(bio);
    free(temp);
    if (out_len) *out_len = decoded_len;
    return buffer;
}

static char* generate_jwt(const char* email) {
    char header[] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char payload[128];
    snprintf(payload, sizeof(payload), "{\"email\":\"%s\"}", email);
    char* header_enc = base64_url_encode((const unsigned char*)header, strlen(header));
    char* payload_enc = base64_url_encode((const unsigned char*)payload, strlen(payload));
    char signing_input[512];
    snprintf(signing_input, sizeof(signing_input), "%s.%s", header_enc, payload_enc);
    unsigned char* signature = HMAC(EVP_sha256(), SECRET_KEY, strlen(SECRET_KEY),
                                    (unsigned char*)signing_input, strlen(signing_input),
                                    NULL, NULL);
    char* signature_enc = base64_url_encode(signature, 32);
    size_t jwt_len = strlen(header_enc) + strlen(payload_enc) + strlen(signature_enc) + 3;
    char* jwt = malloc(jwt_len);
    snprintf(jwt, jwt_len, "%s.%s.%s", header_enc, payload_enc, signature_enc);
    free(header_enc);
    free(payload_enc);
    free(signature_enc);
    return jwt;
}

static int verify_jwt(const char* jwt, char* out_email, size_t out_email_size) {
    const char* dot1 = strchr(jwt, '.');
    if (!dot1) return 0;
    const char* dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return 0;
    int header_len = dot1 - jwt;
    int payload_len = dot2 - (dot1 + 1);
    int signature_len = strlen(dot2 + 1);
    if (header_len <= 0 || payload_len <= 0 || signature_len <= 0) return 0;
    char header_b64[256], payload_b64[256], signature_b64[256];
    if (header_len >= (int)sizeof(header_b64) || payload_len >= (int)sizeof(payload_b64) || signature_len >= (int)sizeof(signature_b64)) return 0;
    strncpy(header_b64, jwt, header_len);
    header_b64[header_len] = '\0';
    strncpy(payload_b64, dot1 + 1, payload_len);
    payload_b64[payload_len] = '\0';
    strcpy(signature_b64, dot2 + 1);
    int hdr_dec_len=0, payload_dec_len=0, sig_dec_len=0;
    unsigned char* header_dec = base64_url_decode(header_b64, &hdr_dec_len);
    unsigned char* payload_dec = base64_url_decode(payload_b64, &payload_dec_len);
    unsigned char* signature_dec = base64_url_decode(signature_b64, &sig_dec_len);
    if (!header_dec || !payload_dec || !signature_dec || sig_dec_len != 32) {
        free(header_dec);
        free(payload_dec);
        free(signature_dec);
        return 0;
    }
    char signing_input[512];
    snprintf(signing_input, sizeof(signing_input), "%s.%s", header_b64, payload_b64);
    unsigned char* computed_sig = HMAC(EVP_sha256(), SECRET_KEY, strlen(SECRET_KEY),
                                       (unsigned char*)signing_input, strlen(signing_input),
                                       NULL, NULL);
    if (memcmp(signature_dec, computed_sig, 32) != 0) {
        free(header_dec);
        free(payload_dec);
        free(signature_dec);
        return 0;
    }
    char email_temp[64];
    if (!extract_json_string((const char*)payload_dec, "\"email\"", email_temp, sizeof(email_temp))) {
        free(header_dec);
        free(payload_dec);
        free(signature_dec);
        return 0;
    }
    strncpy(out_email, email_temp, out_email_size - 1);
    out_email[out_email_size - 1] = '\0';
    free(header_dec);
    free(payload_dec);
    free(signature_dec);
    return 1;
}

static void handle_register(int sock, const char* body, size_t len) {
    char email[32] = {0}, password[64] = {0};
    if (!extract_json_string(body, "\"email\"", email, sizeof(email)) ||
        !extract_json_string(body, "\"password\"", password, sizeof(password))) {
        printf("Bad request.\n");
        write(sock, HTTP_400, strlen(HTTP_400));
        return;
    }
    uint8_t passhash[32];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, passhash, NULL);
    EVP_MD_CTX_free(mdctx);
    if (!create_user(email, passhash)) {
        // Print debug message
        printf("User exists or database is full.\n");
        const char* err = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 44\r\n\r\n{\"error\":\"User exists or database is full.\"}";
        write(sock, err, strlen(err));
        return;
    }
    char* jwt = generate_jwt(email);
    int body_len = (int)(strlen(jwt) + strlen(email) + 23);
    char response[1024];
    int resp_len = snprintf(response, sizeof(response),
                            "%s%d\r\n\r\n{\"token\":\"%s\",\"email\":\"%s\"}",
                            HTTP_200, body_len, jwt, email);
    write(sock, response, resp_len);
    free(jwt);
}

static void handle_login(int sock, const char* body, size_t len) {
    char email[32] = {0}, password[64] = {0};
    if (!extract_json_string(body, "\"email\"", email, sizeof(email)) ||
        !extract_json_string(body, "\"password\"", password, sizeof(password))) {
        write(sock, HTTP_400, strlen(HTTP_400));
        return;
    }
    User* user = find_user(email);
    if (!user) {
        write(sock, HTTP_401, strlen(HTTP_401));
        return;
    }
    uint8_t passhash[32];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, passhash, NULL);
    EVP_MD_CTX_free(mdctx);
    if (memcmp(user->passhash, passhash, 32) != 0) {
        write(sock, HTTP_401, strlen(HTTP_401));
        return;
    }
    char* jwt = generate_jwt(email);
    int body_len = (int)(strlen(jwt) + strlen(email) + 23);
    char response[1024];
    int resp_len = snprintf(response, sizeof(response),
                            "%s%d\r\n\r\n{\"token\":\"%s\",\"email\":\"%s\"}",
                            HTTP_200, body_len, jwt, email);
    write(sock, response, resp_len);
    free(jwt);
}

static void handle_delete(int sock, const char* request, size_t len) {
    const char* auth_ptr = strstr(request, "Authorization:");
    if (!auth_ptr) {
        const char* no_auth = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 29\r\n\r\n{\"error\":\"Missing JWT token\"}";
        write(sock, no_auth, strlen(no_auth));
        return;
    }
    auth_ptr += 14;
    while (*auth_ptr == ' ' || *auth_ptr == '\t') auth_ptr++;
    if (strncmp(auth_ptr, "Bearer ", 7) != 0) {
        const char* bad_auth = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 36\r\n\r\n{\"error\":\"Authorization not Bearer\"}";
        write(sock, bad_auth, strlen(bad_auth));
        return;
    }
    const char* token = auth_ptr + 7;
    const char* line_end = strstr(token, "\r\n");
    char token_buf[512];
    if (!line_end) {
        // no CRLF found, fallback or entire rest is token?
        strncpy(token_buf, token, sizeof(token_buf)-1);
        token_buf[sizeof(token_buf)-1] = '\0';
    } else {
        size_t len = line_end - token;
        if (len >= sizeof(token_buf)) len = sizeof(token_buf) - 1;
        memcpy(token_buf, token, len);
        token_buf[len] = '\0';
    }
    char email[32];
    if (!verify_jwt(token_buf, email, sizeof(email))) {
        const char* invalid = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 23\r\n\r\n{\"error\":\"Invalid JWT\"}";
        write(sock, invalid, strlen(invalid));
        return;
    }
    if (!remove_user(email)) {
        const char* not_found = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 26\r\n\r\n{\"error\":\"User not found\"}";
        write(sock, not_found, strlen(not_found));
        return;
    }
    const char* success_body = "{\"message\":\"User deleted\"}";
    char response[256];
    int body_len = strlen(success_body);
    int resp_len = snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s",
        body_len, success_body
    );
    write(sock, response, resp_len);

}

static int recv_full_request(int sock, char* buf, int buf_size) {
    int total_read = 0;
    int content_length = 0;
    int header_ended = 0;
    int body_start = 0;

    while (1) {
        int r = read(sock, buf + total_read, buf_size - 1 - total_read);
        if (r <= 0) {
            // client closed or error
            return (total_read > 0) ? total_read : r;
        }
        total_read += r;
        buf[total_read] = '\0';

        if (!header_ended) {
            // Look for end of headers
            char* hdr_end = strstr(buf, "\r\n\r\n");
            if (hdr_end) {
                header_ended = 1;
                body_start = (hdr_end + 4) - buf;

                // Parse Content-Length
                content_length = 0;
                char* cl = strcasestr(buf, "Content-Length:");
                if (cl) {
                    cl += 15;
                    while (*cl && isspace((unsigned char)*cl)) cl++;
                    content_length = atoi(cl);
                }
            }
        }

        if (header_ended) {
            int body_bytes = total_read - body_start;
            if (body_bytes >= content_length) {
                return total_read;
            }
        }

        if (total_read == buf_size - 1) {
            return total_read;
        }
    }
}

int main() {
    init_users();
    printf("Server initialized. Listening on port %d...\n", SERVER_PORT);
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(SERVER_PORT);
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }
    if (listen(server_fd, 128) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }
    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        char buffer[MAX_BUFFER];
        int bytes_read = recv_full_request(client_fd, buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            close(client_fd);
            continue;
        }
        buffer[bytes_read] = '\0';
        char method[8] = {0}, path[64] = {0}, version[16] = {0};
        sscanf(buffer, "%7s %63s %15s", method, path, version);
        char* body_ptr = strstr(buffer, "\r\n\r\n");
        size_t body_len = 0;
        if (body_ptr) {
            body_ptr += 4;
            body_len = bytes_read - (body_ptr - buffer);
        }
        if (strcmp(method, "POST") == 0 && strcmp(path, "/register") == 0) {
            handle_register(client_fd, body_ptr, body_len);
        } else if (strcmp(method, "POST") == 0 && strcmp(path, "/login") == 0) {
            handle_login(client_fd, body_ptr, body_len);
        } else if (strcmp(method, "DELETE") == 0 && strcmp(path, "/delete") == 0) {
            handle_delete(client_fd, buffer, bytes_read);
        } else {
            const char* nf = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: 14\r\n\r\n404 Not Found\n";
            write(client_fd, nf, strlen(nf));
        }
        close(client_fd);
    }
    close(server_fd);
    return 0;
}
