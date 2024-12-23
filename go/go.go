package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "hash"
    "log"
    "net/http"
    "strings"
    "sync"
    "time"

    "golang.org/x/crypto/bcrypt"
    "golang.org/x/sync/singleflight"
)

// --------------------------------------------------------------------
// Optimized concurrent user store
// --------------------------------------------------------------------

type UserStore struct {
    shards    [256]userShard
}

type userShard struct {
    sync.RWMutex
    users map[string]string
}

func NewUserStore() *UserStore {
    store := &UserStore{}
    for i := range store.shards {
        store.shards[i].users = make(map[string]string)
    }
    return store
}

func (s *UserStore) getShard(email string) *userShard {
    return &s.shards[uint8(email[0])]
}

func (s *UserStore) Get(email string) (string, bool) {
    shard := s.getShard(email)
    shard.RLock()
    pass, ok := shard.users[email]
    shard.RUnlock()
    return pass, ok
}

func (s *UserStore) Set(email, pass string) {
    shard := s.getShard(email)
    shard.Lock()
    shard.users[email] = pass
    shard.Unlock()
}

func (s *UserStore) Delete(email string) {
    shard := s.getShard(email)
    shard.Lock()
    delete(shard.users, email)
    shard.Unlock()
}

var (
    // Optimized user store with sharding
    users = NewUserStore()

    // Shared secret key used for signing and verifying JWTs
    jwtSecret = []byte("super-secret-key")

    // Pre-computed JWT components
    jwtHeader    = []byte(`{"alg":"HS256","typ":"JWT"}`)
    jwtHeaderB64 = base64.RawURLEncoding.EncodeToString(jwtHeader)

    // Pool of builders for string operations
    builderPool = sync.Pool{
        New: func() interface{} {
            return new(strings.Builder)
        },
    }

    // Pool of byte slices for JWT operations
    bufferPool = sync.Pool{
        New: func() interface{} {
            return make([]byte, 0, 512)
        },
    }

    // Pool of HMAC instances for JWT operations
    hmacPool = sync.Pool{
        New: func() interface{} {
            return hmac.New(sha256.New, jwtSecret)
        },
    }

    // Request deduplication
    requestGroup singleflight.Group
)

// --------------------------------------------------------------------
// Utility: Send JSON response
// --------------------------------------------------------------------

func sendJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    if payload != nil {
        json.NewEncoder(w).Encode(payload)
    }
}

// --------------------------------------------------------------------
// Structs for parsing / returning JSON
// --------------------------------------------------------------------

type Credentials struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

// JWT claims (payload) structure
type JWTClaims struct {
    Email string `json:"email"`
    Exp   int64  `json:"exp"` // Unix timestamp
}

// Response for successful login/register
type AuthResponse struct {
    Token string `json:"token"`
}

// --------------------------------------------------------------------
// Password utilities (bcrypt)
// --------------------------------------------------------------------

func hashPassword(password string) (string, error) {
    // Use a lower cost for development/testing
    // In production, use bcrypt.DefaultCost
    hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), 4)
    if err != nil {
        return "", err
    }
    return string(hashedBytes), nil
}

func checkPassword(hashed, plain string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
    return err == nil
}

// --------------------------------------------------------------------
// JWT Generation and Verification (manually using HMAC-SHA256)
// --------------------------------------------------------------------

// Generate a JWT string containing the user’s email and an expiration time
func generateJWT(email string) (string, error) {
    // Get buffer from pool
    buf := bufferPool.Get().([]byte)
    buf = buf[:0]
    defer bufferPool.Put(buf)

    // Get builder from pool
    builder := builderPool.Get().(*strings.Builder)
    builder.Reset()
    defer builderPool.Put(builder)

    // 1. Write header
    builder.WriteString(jwtHeaderB64)
    builder.WriteByte('.')

    // 2. Create the payload
    claims := JWTClaims{
        Email: email,
        Exp:   time.Now().Add(time.Hour).Unix(),
    }
    
    // Marshal directly into our buffer
    buf, err := json.Marshal(claims)
    if err != nil {
        return "", err
    }

    // Encode payload
    payload := base64.RawURLEncoding.EncodeToString(buf)
    builder.WriteString(payload)

    signingInput := builder.String()

    // 3. Sign with HMAC-SHA256
    mac := hmacPool.Get().(hash.Hash)
    mac.Reset()
    mac.Write([]byte(signingInput))
    signature := base64.RawURLEncoding.EncodeToString(mac.Sum(buf[:0]))
    hmacPool.Put(mac)

    // 4. Build final token
    builder.WriteByte('.')
    builder.WriteString(signature)

    return builder.String(), nil
}

// verifyJWT parses the token, verifies signature and checks expiry
func verifyJWT(token string) (*JWTClaims, error) {
    parts := strings.Split(token, ".")
    if len(parts) != 3 {
        return nil, fmt.Errorf("invalid token format")
    }

    // Use string builder for concatenation
    var builder strings.Builder
    builder.WriteString(parts[0])
    builder.WriteString(".")
    builder.WriteString(parts[1])
    signingInput := builder.String()

    // Use HMAC from pool
    mac := hmacPool.Get().(hash.Hash)
    mac.Reset()
    mac.Write([]byte(signingInput))
    expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
    hmacPool.Put(mac)

    if !hmac.Equal([]byte(parts[2]), []byte(expectedSignature)) {
        return nil, fmt.Errorf("invalid signature")
    }

    // Decode payload
    decodedPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        return nil, fmt.Errorf("failed to decode payload: %v", err)
    }

    var claims JWTClaims
    if err := json.Unmarshal(decodedPayload, &claims); err != nil {
        return nil, fmt.Errorf("failed to unmarshal claims: %v", err)
    }

    // Check expiration
    if time.Now().Unix() > claims.Exp {
        return nil, fmt.Errorf("token expired")
    }

    return &claims, nil
}

// --------------------------------------------------------------------
// Handlers
// --------------------------------------------------------------------

// POST /register
// Expects JSON { "email": "...", "password": "..." }
func registerHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }

    var creds Credentials
    if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    if creds.Email == "" || creds.Password == "" {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    // Check if user exists using optimized store
    if _, exists := users.Get(creds.Email); exists {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    // Hash password with lower cost for benchmarking
    hashed, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 4)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    // Store in sharded map
    users.Set(creds.Email, string(hashed))

    // Generate JWT with request deduplication
    token, err, _ := requestGroup.Do(creds.Email, func() (interface{}, error) {
        return generateJWT(creds.Email)
    })

    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    // Write response
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(AuthResponse{Token: token.(string)})
}

// POST /login
// Expects JSON { "email": "...", "password": "..." }
func loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
        return
    }

    var creds Credentials
    if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
        sendJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
        return
    }

    if creds.Email == "" || creds.Password == "" {
        sendJSON(w, http.StatusBadRequest, map[string]string{"error": "Email and password required"})
        return
    }

    // Get hashed password from optimized store
    hashed, exists := users.Get(creds.Email)
    if !exists {
        sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
        return
    }

    // Compare password
    if !checkPassword(hashed, creds.Password) {
        sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
        return
    }

    // Generate JWT
    token, err := generateJWT(creds.Email)
    if err != nil {
        sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to generate token"})
        return
    }

    sendJSON(w, http.StatusOK, AuthResponse{Token: token})
}

// DELETE /delete
// Requires Authorization: Bearer <JWT>
func deleteHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodDelete {
        sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
        return
    }

    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "Missing Authorization header"})
        return
    }

    parts := strings.Split(authHeader, " ")
    if len(parts) != 2 || parts[0] != "Bearer" {
        sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "Malformed Authorization header"})
        return
    }

    token := parts[1]
    claims, err := verifyJWT(token)
    if err != nil || claims.Email == "" {
        sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid or expired token"})
        return
    }

    // Attempt to delete user
    users.Delete(claims.Email)
    sendJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// --------------------------------------------------------------------
// Main
// --------------------------------------------------------------------

func main() {
    // Configure server with optimized settings
    server := &http.Server{
        Addr: ":3000",
        ReadTimeout:  5 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  120 * time.Second,
        Handler: http.NewServeMux(),
        // Optimize TCP settings
        ReadHeaderTimeout: 2 * time.Second,
        MaxHeaderBytes:    1 << 20, // 1MB
    }

    // Register handlers
    mux := server.Handler.(*http.ServeMux)
    mux.HandleFunc("/register", registerHandler)
    mux.HandleFunc("/login", loginHandler)
    mux.HandleFunc("/delete", deleteHandler)

    log.Fatal(server.ListenAndServe())
}
