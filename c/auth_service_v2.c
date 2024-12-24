#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/event.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <sys/mman.h>
#include <stdatomic.h>

#define SERVER_PORT 3000
#define MAX_BUFFER 4096
#define MAX_USERS (1 << 16)  // 65536 users
#define THREAD_POOL_SIZE 8
#define HASH_BITS 16
#define HASH_SIZE (1 << HASH_BITS)
#define HASH_MASK (HASH_SIZE - 1)

// Pre-computed HTTP responses
static const char* HTTP_200 = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: ";
static const char* HTTP_400 = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: 35\r\n\r\n{\"error\":\"Missing email or password\"}";
static const char* HTTP_401 = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: 41\r\n\r\n{\"error\":\"Invalid email or password.\"}";

// Lock-free user storage using memory mapping
typedef struct {
    uint32_t hash;           // Hash of email for quick comparison
    char email[32];          // Fixed size email
    uint8_t passhash[32];    // SHA256 hash of password
    uint8_t in_use;         // Atomic flag
    uint8_t padding[7];     // Align to 64 bytes (cache line)
} __attribute__((aligned(64))) User;

// Shared memory user database
static User* users;
static atomic_uint user_count = 0;

// Thread pool
typedef struct {
    int client_sock;
    char* request;
    size_t len;
} Task;

typedef struct {
    Task* tasks;
    _Atomic int front;
    _Atomic int rear;
    _Atomic int size;
    int capacity;
} TaskQueue;

static TaskQueue task_queue;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

// Fast hash function for strings
static inline uint32_t fnv1a_hash(const char* str) {
    uint32_t hash = 2166136261u;
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 16777619u;
    }
    return hash;
}

// Initialize the user database
void init_users() {
    // Map anonymous memory for users
    users = mmap(NULL, MAX_USERS * sizeof(User), 
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (users == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
}

// Find user by email using direct mapping
static inline User* find_user(const char* email) {
    uint32_t hash = fnv1a_hash(email);
    uint32_t idx = hash & HASH_MASK;
    
    // Linear probing
    for (uint32_t i = 0; i < HASH_SIZE; i++) {
        User* user = &users[idx];
        if (!user->in_use) return NULL;
        if (user->hash == hash && strcmp(user->email, email) == 0) {
            return user;
        }
        idx = (idx + 1) & HASH_MASK;
    }
    return NULL;
}

// Create user with linear probing
static inline int create_user(const char* email, const uint8_t* passhash) {
    uint32_t hash = fnv1a_hash(email);
    uint32_t idx = hash & HASH_MASK;
    
    // Linear probing
    for (uint32_t i = 0; i < HASH_SIZE; i++) {
        User* user = &users[idx];
        if (!__atomic_test_and_set(&user->in_use, __ATOMIC_SEQ_CST)) {
            user->hash = hash;
            strncpy(user->email, email, sizeof(user->email) - 1);
            memcpy(user->passhash, passhash, 32);
            atomic_fetch_add(&user_count, 1);
            return 1;
        }
        idx = (idx + 1) & HASH_MASK;
    }
    return 0;
}

// Fast JSON field extraction
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

// Handle login request
static void handle_login(int sock, const char* body, size_t len) {
    char email[32] = {0};
    char password[64] = {0};
    
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
    
    // Hash password using EVP
    uint8_t hash[32];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned int md_len;
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, hash, &md_len);
    EVP_MD_CTX_free(mdctx);
    
    if (memcmp(user->passhash, hash, 32) != 0) {
        write(sock, HTTP_401, strlen(HTTP_401));
        return;
    }
    
    // Generate simple token (in real world, use proper JWT)
    char response[256];
    int resp_len = snprintf(response, sizeof(response),
                          "%s%d\r\n\r\n{\"token\":\"user:%s\",\"email\":\"%s\"}",
                          HTTP_200, (int)strlen(email) + 24, email, email);
    write(sock, response, resp_len);
}

// Handle register request
static void handle_register(int sock, const char* body, size_t len) {
    char email[32] = {0};
    char password[64] = {0};
    
    if (!extract_json_string(body, "\"email\"", email, sizeof(email)) ||
        !extract_json_string(body, "\"password\"", password, sizeof(password))) {
        write(sock, HTTP_400, strlen(HTTP_400));
        return;
    }
    
    // Hash password using EVP
    uint8_t hash[32];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned int md_len;
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, hash, &md_len);
    EVP_MD_CTX_free(mdctx);
    
    if (!create_user(email, hash)) {
        const char* error = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 45\r\n\r\n{\"error\":\"User exists or database is full.\"}";
        write(sock, error, strlen(error));
        return;
    }
    
    // Return success with token
    char response[256];
    int resp_len = snprintf(response, sizeof(response),
                          "%s%d\r\n\r\n{\"token\":\"user:%s\",\"email\":\"%s\"}",
                          HTTP_200, (int)strlen(email) + 24, email, email);
    write(sock, response, resp_len);
}

// Fast HTTP request parsing and handling
static void handle_request(int sock, char* req, size_t len) {
    // Fast method check using first byte
    if (req[0] == 'P') {  // POST
        char* path = strchr(req, ' ') + 1;
        char* body = strstr(req, "\r\n\r\n");
        if (!body) return;
        body += 4;
        
        if (strncmp(path, "/login", 6) == 0) {
            handle_login(sock, body, len - (body - req));
        } else if (strncmp(path, "/register", 9) == 0) {
            handle_register(sock, body, len - (body - req));
        }
    }
}

// Worker thread function
static void* worker_thread(void* arg) {
    while (1) {
        Task task;
        
        pthread_mutex_lock(&queue_mutex);
        while (task_queue.size == 0) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        
        task = task_queue.tasks[task_queue.front];
        task_queue.front = (task_queue.front + 1) % task_queue.capacity;
        task_queue.size--;
        pthread_mutex_unlock(&queue_mutex);
        
        handle_request(task.client_sock, task.request, task.len);
        free(task.request);
        close(task.client_sock);
    }
    return NULL;
}

int main() {
    // Initialize user database
    init_users();
    
    // Initialize task queue
    task_queue.capacity = 1024;
    task_queue.tasks = malloc(sizeof(Task) * task_queue.capacity);
    task_queue.front = task_queue.rear = task_queue.size = 0;
    
    // Create thread pool
    pthread_t threads[THREAD_POOL_SIZE];
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_create(&threads[i], NULL, worker_thread, NULL);
    }
    
    // Create server socket
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(server_sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    
    // Increase socket buffers
    int buf_size = 1024 * 1024;
    setsockopt(server_sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    setsockopt(server_sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    
    // Bind and listen
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(SERVER_PORT)
    };
    
    if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    
    if (listen(server_sock, SOMAXCONN) < 0) {
        perror("listen");
        return 1;
    }
    
    // Create kqueue
    int kq = kqueue();
    if (kq < 0) {
        perror("kqueue");
        return 1;
    }
    
    // Add server socket to kqueue
    struct kevent ev;
    EV_SET(&ev, server_sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0) {
        perror("kevent");
        return 1;
    }
    
    printf("Server listening on port %d...\n", SERVER_PORT);
    
    // Event loop
    struct kevent events[1024];
    while (1) {
        int n = kevent(kq, NULL, 0, events, 1024, NULL);
        if (n < 0) {
            perror("kevent wait");
            continue;
        }
        
        for (int i = 0; i < n; i++) {
            if (events[i].ident == (uintptr_t)server_sock) {
                // Accept new connection
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
                if (client_sock < 0) continue;
                
                // Set non-blocking
                int flags = fcntl(client_sock, F_GETFL, 0);
                fcntl(client_sock, F_SETFL, flags | O_NONBLOCK);
                
                // Add to kqueue
                EV_SET(&ev, client_sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
                if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0) {
                    close(client_sock);
                    continue;
                }
            } else {
                // Handle client request
                int client_sock = events[i].ident;
                char* buffer = malloc(MAX_BUFFER);
                ssize_t n = recv(client_sock, buffer, MAX_BUFFER - 1, 0);
                
                if (n > 0) {
                    buffer[n] = '\0';
                    Task task = {client_sock, buffer, n};
                    
                    pthread_mutex_lock(&queue_mutex);
                    if (task_queue.size < task_queue.capacity) {
                        task_queue.tasks[task_queue.rear] = task;
                        task_queue.rear = (task_queue.rear + 1) % task_queue.capacity;
                        task_queue.size++;
                        pthread_cond_signal(&queue_cond);
                        pthread_mutex_unlock(&queue_mutex);
                    } else {
                        pthread_mutex_unlock(&queue_mutex);
                        free(buffer);
                        close(client_sock);
                    }
                } else {
                    free(buffer);
                    close(client_sock);
                }
            }
        }
    }
    
    return 0;
}
