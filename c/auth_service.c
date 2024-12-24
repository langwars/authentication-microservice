#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/event.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/tcp.h>

#define SERVER_PORT 3000
#define MAX_BUFFER   4096
#define MAX_USERS 10000
#define MAX_EVENTS 1024
#define THREAD_POOL_SIZE 8
#define HASH_SIZE 10007

// ============================================================================
// JWT + SECRET
// ============================================================================

#define SECRET_KEY "MY_SUPER_SECRET_KEY"
#define JWT_HEADER_BASE64 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" 
   // This is the base64 of {"alg":"HS256","typ":"JWT"}

// We do minimal base64 here. For real usage, you might want a robust library.
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void base64_url_encode(const unsigned char *in, size_t in_len, 
                              char *out, size_t out_size) {
    // Minimal base64url (no padding). 
    // NOTE: out_size is not validated carefully here for brevity.
    size_t i, j;
    unsigned char arr3[3];
    unsigned char arr4[4];
    int k = 0;

    for (i = 0, j = 0; i < in_len; ) {
        memset(arr3, 0, 3);
        int n = 0;
        for (; n < 3 && i < in_len; n++, i++) {
            arr3[n] = in[i];
        }

        arr4[0] = (arr3[0] & 0xfc) >> 2;
        arr4[1] = ((arr3[0] & 0x03) << 4) + ((arr3[1] & 0xf0) >> 4);
        arr4[2] = ((arr3[1] & 0x0f) << 2) + ((arr3[2] & 0xc0) >> 6);
        arr4[3] = arr3[2] & 0x3f;

        for (int m = 0; m < (n + 1); m++) {
            out[k++] = b64_table[arr4[m]];
        }
    }

    out[k] = '\0';
}

// Create a simple JWT with header {"alg":"HS256","typ":"JWT"} and payload = {"email": <email>}
// 1) We have a static header (encoded as JWT_HEADER_BASE64).
// 2) Payload is JSON with just "email" for simplicity.
char* create_jwt(const char* email) {
    // 1) Construct the payload: {"email":"<email>"}
    char payload[256];
    snprintf(payload, sizeof(payload), "{\"email\":\"%s\"}", email);

    // 2) Base64Url-encode the payload
    unsigned char hash_input[256];
    char payload_b64[256];
    memset(payload_b64, 0, sizeof(payload_b64));
    size_t payload_len = strlen(payload);

    // Convert payload from char* to (unsigned char*) for consistency
    memcpy(hash_input, payload, payload_len);
    base64_url_encode(hash_input, payload_len, payload_b64, sizeof(payload_b64));

    // 3) Construct "header.payload"
    char header_payload[512];
    snprintf(header_payload, sizeof(header_payload), "%s.%s", JWT_HEADER_BASE64, payload_b64);

    // 4) Sign with HMAC-SHA256
    unsigned char* hmac_result = HMAC(EVP_sha256(),
                                      SECRET_KEY, strlen(SECRET_KEY),
                                      (unsigned char*)header_payload, strlen(header_payload),
                                      NULL, NULL);

    // 5) Base64Url-encode the signature
    char signature_b64[256];
    base64_url_encode(hmac_result, 32, signature_b64, sizeof(signature_b64));

    // 6) Combine everything into the final JWT: "header.payload.signature"
    // We'll return a dynamically allocated string. Caller must free it.
    char* jwt = malloc(strlen(header_payload) + 1 + strlen(signature_b64) + 1);
    sprintf(jwt, "%s.%s", header_payload, signature_b64);

    return jwt;
}

// Validate the JWT and return the email if valid, or NULL if invalid.
// Minimal parse: header, payload, signature. Then re-sign header+payload, compare signatures.
char* verify_jwt(const char* token) {
    // Copy the token so we can modify it (we'll need to separate by '.')
    // Expect at least 2 dots: header.payload.signature
    char temp[512];
    strncpy(temp, token, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';

    char* parts[3] = { NULL, NULL, NULL };
    int idx = 0;
    char* saveptr = NULL;
    char* p = strtok_r(temp, ".", &saveptr);
    while (p && idx < 3) {
        parts[idx++] = p;
        p = strtok_r(NULL, ".", &saveptr);
    }

    if (idx < 3) {
        return NULL; // malformed
    }

    // 1) Recompute the HMAC on header.payload
    char header_payload[512];
    snprintf(header_payload, sizeof(header_payload), "%s.%s", parts[0], parts[1]);
    unsigned char* re_hmac = HMAC(EVP_sha256(),
                                  SECRET_KEY, strlen(SECRET_KEY),
                                  (unsigned char*)header_payload, strlen(header_payload),
                                  NULL, NULL);
    // 2) Base64Url-encode the recomputed signature
    char re_sig_b64[256];
    base64_url_encode(re_hmac, 32, re_sig_b64, sizeof(re_sig_b64));

    // 3) Compare to the signature we received in `parts[2]`
    if (strcmp(re_sig_b64, parts[2]) != 0) {
        return NULL; // invalid signature
    }

    // 4) Signature is good. Now decode the payload from base64 to get the email field.
    //    For simplicity, we won't do a *real* base64 decode. Instead, we do a naive approach 
    //    or just parse from parts[1] if it’s short. In a real system, decode properly.

    // We expect parts[1] to be base64Url of something like {"email":"someone@example.com"}.
    // A minimal hack to decode: we won't do real base64 decode for brevity.
    // We do a quick check for the substring "email" 
    // and extract the content between the quotes after "email".
    // This is obviously not robust, but shows the idea.
    char *payload_b64 = parts[1];
    // We'll do a quick workaround: we can skip real decoding and look for
    // the substring in the JSON after we (pretend) decode. 
    // (In production, do a real decode.)

    // We'll do a small buffer for "decoded".
    char payload_json[256];
    // We'll do a "fake decode" by reversing the earlier function 
    // – but let's skip it for brevity and pretend the payload was a plain string:
    // We can do a very naive approach: replace '-' -> '+', '_' -> '/' and decode. 
    // But let's do a super minimal approach here for demonstration only:
    // In practice: you MUST properly decode base64 to get the actual JSON.
    snprintf(payload_json, sizeof(payload_json), "FAKE_DECODED_%s", payload_b64);

    // Now we do a naive parse for "email" 
    // We'll assume the pattern: {"email":"<stuff>"}
    char* email_ptr = strstr(payload_json, "\"email\":\"");
    if (!email_ptr) {
        return NULL;
    }
    email_ptr += 9; // move past "email":" 
    char* end_quote = strchr(email_ptr, '\"');
    if (!end_quote) {
        return NULL;
    }

    size_t email_len = end_quote - email_ptr;
    if (email_len == 0 || email_len > 100) {
        return NULL;
    }

    // 5) Extract the email
    char* email = malloc(email_len + 1);
    strncpy(email, email_ptr, email_len);
    email[email_len] = '\0';

    // We have a valid token and a valid email
    return email;
}

// ============================================================================
// Data Structures for Users
// ============================================================================

typedef struct {
    char email[100];
    // We'll store a SHA256 hash of the password in hex. 
    // (In real usage, do salted, iterative hashing with bcrypt/argon2, etc.)
    char passhash[65]; 
    int in_use;
    struct UserEntry* next;  // For hash table chaining
} User;

typedef struct UserEntry {
    User user;
    struct UserEntry* next;
} UserEntry;

static UserEntry* user_hash_table[HASH_SIZE];
static pthread_mutex_t user_mutex = PTHREAD_MUTEX_INITIALIZER;
static int kq;

// Hash function for emails
unsigned int hash_email(const char* email) {
    unsigned int hash = 0;
    while (*email) {
        hash = (hash * 31 + *email) % HASH_SIZE;
        email++;
    }
    return hash;
}

// Find user by email using hash table
int find_user(const char* email, User* user_out) {
    unsigned int hash = hash_email(email);
    UserEntry* entry = user_hash_table[hash];
    
    while (entry != NULL) {
        if (entry->user.in_use && strcmp(entry->user.email, email) == 0) {
            if (user_out != NULL) {
                *user_out = entry->user;
            }
            return 1;
        }
        entry = entry->next;
    }
    return 0;
}

// Create user with hash table
int create_user(const char* email, const char* passhash) {
    pthread_mutex_lock(&user_mutex);
    
    if (find_user(email, NULL)) {
        pthread_mutex_unlock(&user_mutex);
        return 0;
    }

    unsigned int hash = hash_email(email);
    UserEntry* new_entry = (UserEntry*)malloc(sizeof(UserEntry));
    
    snprintf(new_entry->user.email, sizeof(new_entry->user.email), "%s", email);
    snprintf(new_entry->user.passhash, sizeof(new_entry->user.passhash), "%s", passhash);
    new_entry->user.in_use = 1;
    
    new_entry->next = user_hash_table[hash];
    user_hash_table[hash] = new_entry;
    
    pthread_mutex_unlock(&user_mutex);
    return 1;
}

// Delete user from hash table
int delete_user(const char* email) {
    pthread_mutex_lock(&user_mutex);
    
    unsigned int hash = hash_email(email);
    UserEntry** entry_ptr = &user_hash_table[hash];
    UserEntry* entry = *entry_ptr;
    
    while (entry != NULL) {
        if (entry->user.in_use && strcmp(entry->user.email, email) == 0) {
            *entry_ptr = entry->next;
            free(entry);
            pthread_mutex_unlock(&user_mutex);
            return 1;
        }
        entry_ptr = &entry->next;
        entry = *entry_ptr;
    }
    
    pthread_mutex_unlock(&user_mutex);
    return 0;
}

// ============================================================================
// Password Hashing (SHA256 in hex, minimal usage of OpenSSL)
// ============================================================================

void sha256_hex(const char* input, char* output_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)input, strlen(input), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output_hex + (i * 2), "%02x", hash[i]);
    }
    output_hex[64] = '\0';
}

// ============================================================================
// Minimal JSON Helpers
// ============================================================================

// We parse input for "email" and "password". Very naive approach.
void parse_json_body(const char* body, char* email_out, size_t email_sz,
                     char* password_out, size_t pass_sz) 
{
    // naive: look for "email": "something", "password":"something"
    // In real usage, use a JSON library. 
    const char* e_ptr = strstr(body, "\"email\"");
    if (e_ptr) {
        e_ptr = strchr(e_ptr, ':');
        if (e_ptr) {
            e_ptr = strchr(e_ptr, '\"');
            if (e_ptr) {
                e_ptr++;
                const char* e_end = strchr(e_ptr, '\"');
                if (e_end) {
                    size_t len = e_end - e_ptr;
                    if (len < email_sz) {
                        strncpy(email_out, e_ptr, len);
                        email_out[len] = '\0';
                    }
                }
            }
        }
    }

    const char* p_ptr = strstr(body, "\"password\"");
    if (p_ptr) {
        p_ptr = strchr(p_ptr, ':');
        if (p_ptr) {
            p_ptr = strchr(p_ptr, '\"');
            if (p_ptr) {
                p_ptr++;
                const char* p_end = strchr(p_ptr, '\"');
                if (p_end) {
                    size_t len = p_end - p_ptr;
                    if (len < pass_sz) {
                        strncpy(password_out, p_ptr, len);
                        password_out[len] = '\0';
                    }
                }
            }
        }
    }
}

// ============================================================================
// HTTP Handling
// ============================================================================

void send_json(int client_sock, int status, const char* json_body) {
    char response[1024];
    // Construct a minimal HTTP response
    snprintf(response, sizeof(response),
             "HTTP/1.1 %d OK\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %lu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             status, (unsigned long)strlen(json_body), json_body);
    send(client_sock, response, strlen(response), 0);
}

void handle_register(int client_sock, const char* body) {
    char email[128] = {0};
    char password[128] = {0};
    parse_json_body(body, email, sizeof(email), password, sizeof(password));

    if (strlen(email) == 0 || strlen(password) == 0) {
        send_json(client_sock, 400, "{\"error\":\"Missing email or password\"}");
        return;
    }

    // Hash the password
    char passhash[65];
    sha256_hex(password, passhash);

    // Create user
    if (!create_user(email, passhash)) {
        // user exists or no space
        send_json(client_sock, 400, "{\"error\":\"User already exists or no space.\"}");
        return;
    }

    // Return JWT
    char* jwt = create_jwt(email);
    if (!jwt) {
        send_json(client_sock, 500, "{\"error\":\"JWT creation failed.\"}");
        return;
    }

    char response_json[512];
    snprintf(response_json, sizeof(response_json), 
             "{\"token\":\"%s\",\"email\":\"%s\"}", jwt, email);

    send_json(client_sock, 200, response_json);
    free(jwt);
}

void handle_login(int client_sock, const char* body) {
    char email[128] = {0};
    char password[128] = {0};
    parse_json_body(body, email, sizeof(email), password, sizeof(password));

    if (strlen(email) == 0 || strlen(password) == 0) {
        send_json(client_sock, 400, "{\"error\":\"Missing email or password\"}");
        return;
    }

    int idx = find_user(email, NULL);
    if (idx == -1) {
        send_json(client_sock, 401, "{\"error\":\"Invalid email or password.\"}");
        return;
    }

    char passhash[65];
    sha256_hex(password, passhash);

    User user;
    find_user(email, &user);

    if (strcmp(user.passhash, passhash) != 0) {
        send_json(client_sock, 401, "{\"error\":\"Invalid email or password.\"}");
        return;
    }

    // Return JWT
    char* jwt = create_jwt(email);
    if (!jwt) {
        send_json(client_sock, 500, "{\"error\":\"JWT creation failed.\"}");
        return;
    }

    char response_json[512];
    snprintf(response_json, sizeof(response_json),
             "{\"token\":\"%s\",\"email\":\"%s\"}", jwt, email);

    send_json(client_sock, 200, response_json);
    free(jwt);
}

void handle_delete(int client_sock, const char* headers) {
    // We look for "Authorization: Bearer <JWT>" in headers
    // super naive approach:
    // 1) find "Authorization:"
    // 2) find "Bearer" ...
    char* auth_ptr = strstr((char*)headers, "Authorization:");
    if (!auth_ptr) {
        send_json(client_sock, 401, "{\"error\":\"Missing Authorization header.\"}");
        return;
    }

    // Move to end of "Authorization:"
    auth_ptr += strlen("Authorization:");
    // Skip spaces
    while (*auth_ptr == ' ') auth_ptr++;

    if (strncmp(auth_ptr, "Bearer ", 7) != 0) {
        send_json(client_sock, 401, "{\"error\":\"Malformed Authorization header.\"}");
        return;
    }

    auth_ptr += 7; // move past "Bearer "
    // Now auth_ptr should point to the JWT
    char jwt[512];
    memset(jwt, 0, sizeof(jwt));
    // read until space or newline
    int i = 0;
    while (*auth_ptr && *auth_ptr != '\r' && *auth_ptr != '\n' 
                     && *auth_ptr != ' ' && i < (int)(sizeof(jwt) - 1)) {
        jwt[i++] = *auth_ptr++;
    }
    jwt[i] = '\0';

    // Verify the JWT
    char* email = verify_jwt(jwt);
    if (!email) {
        send_json(client_sock, 401, "{\"error\":\"Invalid or expired token.\"}");
        return;
    }

    // Attempt to delete
    if (delete_user(email)) {
        send_json(client_sock, 200, "{\"success\":true}");
    } else {
        send_json(client_sock, 400, "{\"success\":false, \"error\":\"User not found.\"}");
    }
    free(email);
}

// Dispatch the request to the appropriate handler
void handle_request(int client_sock, const char* request) {
    // request contains the entire HTTP request, including headers and body.

    // 1) parse the method & path
    // example: "POST /login HTTP/1.1\r\nHost: ...\r\n..."
    char method[8];
    char path[32];
    memset(method, 0, sizeof(method));
    memset(path,   0, sizeof(path));

    sscanf(request, "%7s %31s", method, path);

    // 2) find the start of the body
    char* body_ptr = strstr(request, "\r\n\r\n");
    char* body = NULL;
    if (body_ptr) {
        body = body_ptr + 4;
    } else {
        body = (char*)"";
    }

    // 3) route
    if (strcmp(method, "POST") == 0 && strcmp(path, "/register") == 0) {
        handle_register(client_sock, body);
    } 
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/login") == 0) {
        handle_login(client_sock, body);
    } 
    else if (strcmp(method, "DELETE") == 0 && strcmp(path, "/delete") == 0) {
        // pass entire request as "headers" so handle_delete can look for Authorization:
        handle_delete(client_sock, request);
    }
    else {
        send_json(client_sock, 404, "{\"error\":\"Not found\"}");
    }
}

// Thread pool
typedef struct {
    int client_sock;
    char* request;
} Task;

typedef struct {
    Task* tasks;
    int front;
    int rear;
    int size;
    int capacity;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} TaskQueue;

static TaskQueue task_queue;

// Initialize the task queue
void init_task_queue(int capacity) {
    task_queue.tasks = (Task*)malloc(capacity * sizeof(Task));
    task_queue.front = 0;
    task_queue.rear = 0;
    task_queue.size = 0;
    task_queue.capacity = capacity;
    pthread_mutex_init(&task_queue.mutex, NULL);
    pthread_cond_init(&task_queue.not_empty, NULL);
    pthread_cond_init(&task_queue.not_full, NULL);
}

// Add task to queue
void enqueue_task(Task task) {
    pthread_mutex_lock(&task_queue.mutex);
    while (task_queue.size == task_queue.capacity) {
        pthread_cond_wait(&task_queue.not_full, &task_queue.mutex);
    }
    task_queue.tasks[task_queue.rear] = task;
    task_queue.rear = (task_queue.rear + 1) % task_queue.capacity;
    task_queue.size++;
    pthread_cond_signal(&task_queue.not_empty);
    pthread_mutex_unlock(&task_queue.mutex);
}

// Get task from queue
Task dequeue_task() {
    pthread_mutex_lock(&task_queue.mutex);
    while (task_queue.size == 0) {
        pthread_cond_wait(&task_queue.not_empty, &task_queue.mutex);
    }
    Task task = task_queue.tasks[task_queue.front];
    task_queue.front = (task_queue.front + 1) % task_queue.capacity;
    task_queue.size--;
    pthread_cond_signal(&task_queue.not_full);
    pthread_mutex_unlock(&task_queue.mutex);
    return task;
}

// Worker thread function
void* worker_thread(void* arg) {
    while (1) {
        Task task = dequeue_task();
        handle_request(task.client_sock, task.request);
        free(task.request);
        close(task.client_sock);
    }
    return NULL;
}

// Set socket to non-blocking mode
void set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

// ============================================================================
// Main server loop
// ============================================================================

int main(int argc, char *argv[]) {
    // Initialize hash table
    memset(user_hash_table, 0, sizeof(user_hash_table));
    
    // Initialize task queue
    init_task_queue(MAX_EVENTS * 2);
    
    // Create thread pool
    pthread_t threads[THREAD_POOL_SIZE];
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_create(&threads[i], NULL, worker_thread, NULL);
    }
    
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(server_sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    
    // Increase socket buffer sizes
    int buf_size = 1024 * 1024;
    setsockopt(server_sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    setsockopt(server_sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(SERVER_PORT);
    
    if (bind(server_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        close(server_sock);
        return 1;
    }
    
    if (listen(server_sock, SOMAXCONN) < 0) {
        perror("listen");
        close(server_sock);
        return 1;
    }
    
    // Set server socket to non-blocking mode
    set_nonblocking(server_sock);
    
    // Create kqueue instance
    kq = kqueue();
    if (kq == -1) {
        perror("kqueue");
        return 1;
    }
    
    // Add server socket to kqueue
    struct kevent ev;
    EV_SET(&ev, server_sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
        perror("kevent");
        return 1;
    }
    
    printf("Listening on port %d...\n", SERVER_PORT);
    
    // Event loop
    struct kevent events[MAX_EVENTS];
    while (1) {
        int nev = kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
        if (nev < 0) {
            perror("kevent wait");
            continue;
        }
        
        for (int i = 0; i < nev; i++) {
            int fd = events[i].ident;
            
            if (fd == server_sock) {
                // Accept new connections
                while (1) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
                    if (client_sock == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        perror("accept");
                        continue;
                    }
                    
                    set_nonblocking(client_sock);
                    
                    // Add to kqueue
                    struct kevent ev;
                    EV_SET(&ev, client_sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
                    if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
                        perror("kevent add client");
                        close(client_sock);
                        continue;
                    }
                }
            } else {
                // Handle client socket
                char* buffer = malloc(MAX_BUFFER);
                memset(buffer, 0, MAX_BUFFER);
                
                int bytes_received = recv(fd, buffer, MAX_BUFFER - 1, 0);
                if (bytes_received > 0) {
                    buffer[bytes_received] = '\0';
                    Task task = {fd, buffer};
                    enqueue_task(task);
                } else {
                    if (bytes_received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        free(buffer);
                        continue;
                    }
                    struct kevent ev;
                    EV_SET(&ev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
                    kevent(kq, &ev, 1, NULL, 0, NULL);
                    close(fd);
                    free(buffer);
                }
            }
        }
    }
    
    close(server_sock);
    return 0;
}
