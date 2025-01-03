package main

import (
	"encoding/json"
	"log"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fasthttp/router"
	"github.com/golang-jwt/jwt/v4"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/argon2"
)

type JSONResponse struct {
	Status  string `json:"status"`
	Success bool   `json:"success"`
}

type registerResponse struct {
	Status string `json:"status"`
	Token  string `json:"token"`
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var (
	mu    sync.RWMutex
	users = make(map[string]string)
)

var jwtSecret = []byte("mySuperSecretKey")

type loginCacheEntry struct {
	Password  string
	Valid     bool
	ExpiresAt int64
}

var (
	loginCache      = make(map[string]loginCacheEntry)
	loginCacheMutex sync.RWMutex
)

const loginCacheTTL = 2 * time.Minute

var hashQueue = make(chan func(), 100)

func init() {
	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			for job := range hashQueue {
				job()
			}
		}()
	}
}

func getCachedLogin(email, password string) (bool, bool) {
	loginCacheMutex.RLock()
	entry, ok := loginCache[email]
	loginCacheMutex.RUnlock()
	if !ok || time.Now().Unix() > entry.ExpiresAt {
		if ok {
			loginCacheMutex.Lock()
			delete(loginCache, email)
			loginCacheMutex.Unlock()
		}
		return false, false
	}
	if entry.Password == password {
		return entry.Valid, true
	}
	return false, false
}

func setCachedLogin(email, password string, valid bool) {
	loginCacheMutex.Lock()
	loginCache[email] = loginCacheEntry{
		Password:  password,
		Valid:     valid,
		ExpiresAt: time.Now().Add(loginCacheTTL).Unix(),
	}
	loginCacheMutex.Unlock()
}

func respondJSON(ctx *fasthttp.RequestCtx, statusCode int, data interface{}) {
	ctx.Response.Header.Set("Content-Type", "application/json")
	ctx.SetStatusCode(statusCode)
	if data != nil {
		jsonBytes, err := json.Marshal(data)
		if err == nil {
			ctx.SetBody(jsonBytes)
		}
	}
}

func generateJWT(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
	})
	return token.SignedString(jwtSecret)
}

func hashPassword(password string) string {
	salt := make([]byte, 16)
	hashed := argon2.IDKey([]byte(password), salt, 1, 32*1024, 2, 32)
	return string(hashed)
}

func asyncHashPassword(email, password string) {
	hashQueue <- func() {
		hashedPassword := hashPassword(password)
		mu.Lock()
		users[email] = hashedPassword
		mu.Unlock()
	}
}

func loginHandler(ctx *fasthttp.RequestCtx) {
	if !ctx.IsPost() {
		respondJSON(ctx, fasthttp.StatusMethodNotAllowed, JSONResponse{Status: "Method not allowed"})
		return
	}
	var req registerRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		respondJSON(ctx, fasthttp.StatusBadRequest, JSONResponse{Status: "Bad request"})
		return
	}
	if req.Email == "" || req.Password == "" {
		respondJSON(ctx, fasthttp.StatusBadRequest, JSONResponse{Status: "Email and password required"})
		return
	}
	if !strings.Contains(req.Email, "@") {
		respondJSON(ctx, fasthttp.StatusBadRequest, JSONResponse{Status: "Invalid email"})
		return
	}
	mu.RLock()
	hashedPwd, found := users[req.Email]
	mu.RUnlock()
	if !found {
		respondJSON(ctx, fasthttp.StatusUnauthorized, JSONResponse{Status: "Invalid email or password"})
		return
	}
	if cachedValid, cached := getCachedLogin(req.Email, req.Password); cached {
		if cachedValid {
			signedToken, _ := generateJWT(req.Email)
			respondJSON(ctx, fasthttp.StatusOK, registerResponse{Status: "OK", Token: signedToken})
			return
		}
		respondJSON(ctx, fasthttp.StatusUnauthorized, JSONResponse{Status: "Invalid email or password"})
		return
	}
	if string(argon2.IDKey([]byte(req.Password), []byte{}, 1, 32*1024, 2, 32)) != hashedPwd {
		respondJSON(ctx, fasthttp.StatusUnauthorized, JSONResponse{Status: "Invalid email or password"})
		return
	}
	setCachedLogin(req.Email, req.Password, true)
	signedToken, _ := generateJWT(req.Email)
	respondJSON(ctx, fasthttp.StatusOK, registerResponse{Status: "OK", Token: signedToken})
}

func registerHandler(ctx *fasthttp.RequestCtx) {
	if !ctx.IsPost() {
		respondJSON(ctx, fasthttp.StatusMethodNotAllowed, JSONResponse{Status: "Method not allowed"})
		return
	}
	var req registerRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		respondJSON(ctx, fasthttp.StatusBadRequest, JSONResponse{Status: "Bad request"})
		return
	}
	if req.Email == "" || req.Password == "" {
		respondJSON(ctx, fasthttp.StatusBadRequest, JSONResponse{Status: "Email and password required"})
		return
	}
	if !strings.Contains(req.Email, "@") {
		respondJSON(ctx, fasthttp.StatusBadRequest, JSONResponse{Status: "Invalid email"})
		return
	}
	mu.RLock()
	_, found := users[req.Email]
	mu.RUnlock()
	if found {
		respondJSON(ctx, fasthttp.StatusBadRequest, JSONResponse{Status: "Email already in use"})
		return
	}
	asyncHashPassword(req.Email, req.Password)
	signedToken, _ := generateJWT(req.Email)
	respondJSON(ctx, fasthttp.StatusOK, registerResponse{Status: "OK", Token: signedToken})
}

func deleteHandler(ctx *fasthttp.RequestCtx) {
	if string(ctx.Method()) != fasthttp.MethodDelete {
		respondJSON(ctx, fasthttp.StatusMethodNotAllowed, JSONResponse{Status: "Method not allowed"})
		return
	}
	authHeader := string(ctx.Request.Header.Peek("Authorization"))
	if !strings.HasPrefix(authHeader, "Bearer ") {
		respondJSON(ctx, fasthttp.StatusUnauthorized, JSONResponse{Status: "Missing or invalid Bearer token"})
		return
	}
	tokenString := authHeader[len("Bearer "):]
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, nil
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		respondJSON(ctx, fasthttp.StatusUnauthorized, JSONResponse{Status: "Invalid token"})
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		respondJSON(ctx, fasthttp.StatusUnauthorized, JSONResponse{Status: "Invalid token claims"})
		return
	}
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		respondJSON(ctx, fasthttp.StatusUnauthorized, JSONResponse{Status: "Invalid email claim"})
		return
	}
	mu.Lock()
	delete(users, email)
	mu.Unlock()
	respondJSON(ctx, fasthttp.StatusOK, JSONResponse{Status: "OK", Success: true})
}

func main() {
	go func() {
		log.Println("Starting pprof server on :6060...")
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	r := router.New()
	r.POST("/login", loginHandler)
	r.POST("/register", registerHandler)
	r.DELETE("/delete", deleteHandler)
	r.NotFound = func(ctx *fasthttp.RequestCtx) {
		respondJSON(ctx, fasthttp.StatusNotFound, JSONResponse{Status: "Not Found"})
	}
	srv := &fasthttp.Server{
		Handler: r.Handler,
		Name:    "FastHTTP-Server",
	}
	log.Println("Starting FastHTTP server on :3000...")
	if err := srv.ListenAndServe(":3000"); err != nil {
		log.Fatalf("Error in ListenAndServe: %v", err)
	}
}
